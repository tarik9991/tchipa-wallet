// Tchipa Wallet — self-custody USDT/Polygon wallet.
//
// Single-file architecture, mirrors the convention of the main Tchipa app.
// Sections: constants, WalletService, screens (Splash, Onboard, Create, Import,
// Home, Receive, Send).

import 'package:bip32/bip32.dart' as bip32;
import 'package:bip39/bip39.dart' as bip39;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:qr_flutter/qr_flutter.dart';
import 'package:web3dart/web3dart.dart';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const String kPolygonRpc = 'https://polygon-rpc.com';
const int kPolygonChainId = 137;

// USDT on Polygon (PoS), 6 decimals.
const String kUsdtAddress = '0xc2132D05D31c914a87C6611C10748AEb04B58e8F';
const int kUsdtDecimals = 6;

// BIP-44 path for Ethereum/EVM accounts.
const String kHdPath = "m/44'/60'/0'/0/0";

// Secure storage keys.
const String kStorageMnemonic = 'tchipa_wallet_mnemonic_v1';

// Minimal ERC-20 ABI (balanceOf, transfer).
const String kErc20Abi =
    '[{"constant":true,"inputs":[{"name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"type":"function"},'
    '{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"}]';

const Color kBg = Color(0xFF0E1116);
const Color kCard = Color(0xFF181C24);
const Color kAccent = Color(0xFF7C5CFF);
const Color kMuted = Color(0xFF8A93A6);

// ---------------------------------------------------------------------------
// WalletService — holds the active EVM account, talks to Polygon.
// ---------------------------------------------------------------------------

class WalletService {
  WalletService._();
  static final WalletService instance = WalletService._();

  final FlutterSecureStorage _storage = const FlutterSecureStorage();
  final Web3Client _client = Web3Client(kPolygonRpc, http.Client());

  EthPrivateKey? _credentials;
  EthereumAddress? _address;
  String? _mnemonic;

  bool get isLoaded => _credentials != null;
  EthereumAddress? get address => _address;
  String? get mnemonic => _mnemonic;

  Future<bool> hasStoredWallet() async {
    final v = await _storage.read(key: kStorageMnemonic);
    return v != null && v.isNotEmpty;
  }

  Future<void> loadFromStorage() async {
    final m = await _storage.read(key: kStorageMnemonic);
    if (m == null || m.isEmpty) return;
    _applyMnemonic(m);
  }

  Future<void> importMnemonic(String mnemonic) async {
    final cleaned =
        mnemonic.trim().split(RegExp(r'\s+')).join(' ').toLowerCase();
    if (!bip39.validateMnemonic(cleaned)) {
      throw const FormatException('Phrase mnémonique invalide.');
    }
    _applyMnemonic(cleaned);
    await _storage.write(key: kStorageMnemonic, value: cleaned);
  }

  Future<void> wipe() async {
    await _storage.delete(key: kStorageMnemonic);
    _credentials = null;
    _address = null;
    _mnemonic = null;
  }

  void _applyMnemonic(String mnemonic) {
    final seed = bip39.mnemonicToSeed(mnemonic);
    final root = bip32.BIP32.fromSeed(seed);
    final child = root.derivePath(kHdPath);
    final pk = child.privateKey;
    if (pk == null) {
      throw StateError('Échec de dérivation de la clé privée.');
    }
    _credentials = EthPrivateKey(pk);
    _address = _credentials!.address;
    _mnemonic = mnemonic;
  }

  Future<BigInt> polBalance() async {
    if (_address == null) return BigInt.zero;
    final v = await _client.getBalance(_address!);
    return v.getInWei;
  }

  Future<BigInt> usdtBalance() async {
    if (_address == null) return BigInt.zero;
    final contract = _erc20();
    final fn = contract.function('balanceOf');
    final res = await _client.call(
      contract: contract,
      function: fn,
      params: [_address!],
    );
    return res.first as BigInt;
  }

  Future<String> sendUsdt({
    required String toHex,
    required BigInt amountWei,
  }) async {
    if (_credentials == null) {
      throw StateError('Wallet non chargée.');
    }
    final contract = _erc20();
    final fn = contract.function('transfer');
    final to = EthereumAddress.fromHex(toHex);
    final tx = Transaction.callContract(
      contract: contract,
      function: fn,
      parameters: [to, amountWei],
    );
    return _client.sendTransaction(
      _credentials!,
      tx,
      chainId: kPolygonChainId,
    );
  }

  DeployedContract _erc20() => DeployedContract(
        ContractAbi.fromJson(kErc20Abi, 'ERC20'),
        EthereumAddress.fromHex(kUsdtAddress),
      );

  // Formats a BigInt amount given its decimals to a trimmed decimal string.
  static String formatAmount(BigInt raw, int decimals, {int displayDp = 6}) {
    if (raw == BigInt.zero) return '0';
    final divisor = BigInt.from(10).pow(decimals);
    final whole = raw ~/ divisor;
    final frac = raw % divisor;
    if (frac == BigInt.zero) return whole.toString();
    var fracStr = frac.toString().padLeft(decimals, '0');
    if (displayDp < decimals) {
      fracStr = fracStr.substring(0, displayDp);
    }
    fracStr = fracStr.replaceFirst(RegExp(r'0+$'), '');
    if (fracStr.isEmpty) return whole.toString();
    return '$whole.$fracStr';
  }

  // Parses a decimal string to a BigInt of the given decimals. Throws on bad input.
  static BigInt parseAmount(String input, int decimals) {
    final s = input.trim().replaceAll(',', '.');
    if (s.isEmpty) throw const FormatException('Montant vide.');
    if (!RegExp(r'^\d+(\.\d+)?$').hasMatch(s)) {
      throw const FormatException('Montant invalide.');
    }
    final parts = s.split('.');
    final whole = BigInt.parse(parts[0]);
    BigInt frac = BigInt.zero;
    if (parts.length == 2) {
      var f = parts[1];
      if (f.length > decimals) f = f.substring(0, decimals);
      f = f.padRight(decimals, '0');
      frac = BigInt.parse(f);
    }
    return whole * BigInt.from(10).pow(decimals) + frac;
  }
}

// ---------------------------------------------------------------------------
// App entrypoint
// ---------------------------------------------------------------------------

void main() => runApp(const TchipaWalletApp());

class TchipaWalletApp extends StatelessWidget {
  const TchipaWalletApp({super.key});

  @override
  Widget build(BuildContext context) {
    final base = ThemeData.dark(useMaterial3: true);
    return MaterialApp(
      title: 'Tchipa Wallet',
      debugShowCheckedModeBanner: false,
      theme: base.copyWith(
        scaffoldBackgroundColor: kBg,
        colorScheme: base.colorScheme.copyWith(
          primary: kAccent,
          surface: kCard,
        ),
        appBarTheme: const AppBarTheme(
          backgroundColor: kBg,
          elevation: 0,
          centerTitle: true,
        ),
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            backgroundColor: kAccent,
            foregroundColor: Colors.white,
            minimumSize: const Size.fromHeight(52),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(14),
            ),
            textStyle:
                const TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
          ),
        ),
      ),
      home: const SplashScreen(),
    );
  }
}

// ---------------------------------------------------------------------------
// SplashScreen — decide route based on stored wallet.
// ---------------------------------------------------------------------------

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});
  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> {
  @override
  void initState() {
    super.initState();
    _route();
  }

  Future<void> _route() async {
    final svc = WalletService.instance;
    final has = await svc.hasStoredWallet();
    if (has) {
      await svc.loadFromStorage();
    }
    if (!mounted) return;
    Navigator.of(context).pushReplacement(
      MaterialPageRoute(
        builder: (_) => has ? const HomeScreen() : const OnboardScreen(),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      backgroundColor: kBg,
      body: Center(child: CircularProgressIndicator(color: kAccent)),
    );
  }
}

// ---------------------------------------------------------------------------
// OnboardScreen — Create or Import.
// ---------------------------------------------------------------------------

class OnboardScreen extends StatelessWidget {
  const OnboardScreen({super.key});
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const SizedBox(height: 48),
              Container(
                width: 84,
                height: 84,
                decoration: BoxDecoration(
                  color: kAccent,
                  borderRadius: BorderRadius.circular(20),
                ),
                alignment: Alignment.center,
                child: const Text(
                  'T',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 48,
                    fontWeight: FontWeight.w800,
                  ),
                ),
              ),
              const SizedBox(height: 24),
              const Text(
                'Tchipa Wallet',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 28,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                'Votre wallet USDT/Polygon en self-custody.\nVous gardez vos clés, vous gardez vos fonds.',
                textAlign: TextAlign.center,
                style: TextStyle(color: kMuted, fontSize: 14, height: 1.4),
              ),
              const Spacer(),
              ElevatedButton(
                onPressed: () => Navigator.of(context).push(
                  MaterialPageRoute(builder: (_) => const CreateWalletScreen()),
                ),
                child: const Text('Créer une nouvelle wallet'),
              ),
              const SizedBox(height: 12),
              OutlinedButton(
                onPressed: () => Navigator.of(context).push(
                  MaterialPageRoute(builder: (_) => const ImportWalletScreen()),
                ),
                style: OutlinedButton.styleFrom(
                  foregroundColor: Colors.white,
                  minimumSize: const Size.fromHeight(52),
                  side: const BorderSide(color: kMuted),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(14),
                  ),
                ),
                child: const Text("J'ai déjà une phrase de récupération"),
              ),
              const SizedBox(height: 24),
            ],
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// CreateWalletScreen — show 12 words, force confirmation.
// ---------------------------------------------------------------------------

class CreateWalletScreen extends StatefulWidget {
  const CreateWalletScreen({super.key});
  @override
  State<CreateWalletScreen> createState() => _CreateWalletScreenState();
}

class _CreateWalletScreenState extends State<CreateWalletScreen> {
  late final String _mnemonic;
  bool _revealed = false;
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    _mnemonic = bip39.generateMnemonic(strength: 128);
  }

  Future<void> _confirm() async {
    setState(() => _saving = true);
    try {
      await WalletService.instance.importMnemonic(_mnemonic);
      if (!mounted) return;
      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const HomeScreen()),
        (_) => false,
      );
    } catch (e) {
      setState(() => _saving = false);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Erreur: $e')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final words = _mnemonic.split(' ');
    return Scaffold(
      appBar: AppBar(title: const Text('Phrase de récupération')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'Notez ces 12 mots dans l\'ordre et gardez-les en lieu sûr. '
                'Quiconque a accès à cette phrase contrôle votre wallet. '
                'Tchipa ne peut PAS la récupérer.',
                style: TextStyle(color: kMuted, height: 1.4),
              ),
              const SizedBox(height: 20),
              Stack(
                children: [
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: kCard,
                      borderRadius: BorderRadius.circular(14),
                    ),
                    child: GridView.builder(
                      shrinkWrap: true,
                      physics: const NeverScrollableScrollPhysics(),
                      gridDelegate:
                          const SliverGridDelegateWithFixedCrossAxisCount(
                        crossAxisCount: 3,
                        childAspectRatio: 2.4,
                        crossAxisSpacing: 8,
                        mainAxisSpacing: 8,
                      ),
                      itemCount: 12,
                      itemBuilder: (_, i) => Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10),
                        alignment: Alignment.centerLeft,
                        decoration: BoxDecoration(
                          color: kBg,
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Text(
                          '${i + 1}. ${words[i]}',
                          style: const TextStyle(
                            color: Colors.white,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                    ),
                  ),
                  if (!_revealed)
                    Positioned.fill(
                      child: GestureDetector(
                        onTap: () => setState(() => _revealed = true),
                        child: Container(
                          decoration: BoxDecoration(
                            color: kCard,
                            borderRadius: BorderRadius.circular(14),
                          ),
                          alignment: Alignment.center,
                          child: const Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Icon(Icons.visibility, color: kAccent, size: 32),
                              SizedBox(height: 8),
                              Text(
                                'Toucher pour révéler',
                                style: TextStyle(color: Colors.white),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ),
                ],
              ),
              const SizedBox(height: 16),
              if (_revealed)
                OutlinedButton.icon(
                  onPressed: () async {
                    await Clipboard.setData(ClipboardData(text: _mnemonic));
                    if (!context.mounted) return;
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Phrase copiée.')),
                    );
                  },
                  icon: const Icon(Icons.copy, size: 18),
                  label: const Text('Copier'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: Colors.white,
                    side: const BorderSide(color: kMuted),
                  ),
                ),
              const Spacer(),
              ElevatedButton(
                onPressed: _revealed && !_saving ? _confirm : null,
                child: _saving
                    ? const SizedBox(
                        height: 22,
                        width: 22,
                        child: CircularProgressIndicator(
                          color: Colors.white,
                          strokeWidth: 2.4,
                        ),
                      )
                    : const Text("J'ai noté la phrase, continuer"),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// ImportWalletScreen — paste an existing mnemonic.
// ---------------------------------------------------------------------------

class ImportWalletScreen extends StatefulWidget {
  const ImportWalletScreen({super.key});
  @override
  State<ImportWalletScreen> createState() => _ImportWalletScreenState();
}

class _ImportWalletScreenState extends State<ImportWalletScreen> {
  final TextEditingController _ctrl = TextEditingController();
  bool _busy = false;
  String? _err;

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    setState(() {
      _busy = true;
      _err = null;
    });
    try {
      await WalletService.instance.importMnemonic(_ctrl.text);
      if (!mounted) return;
      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const HomeScreen()),
        (_) => false,
      );
    } catch (e) {
      setState(() {
        _busy = false;
        _err = e.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Importer une wallet')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'Collez votre phrase de 12 ou 24 mots, séparés par des espaces.',
                style: TextStyle(color: kMuted, height: 1.4),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: _ctrl,
                maxLines: 4,
                style: const TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  filled: true,
                  fillColor: kCard,
                  hintText: 'word1 word2 word3 ...',
                  hintStyle: const TextStyle(color: kMuted),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(14),
                    borderSide: BorderSide.none,
                  ),
                  errorText: _err,
                ),
              ),
              const Spacer(),
              ElevatedButton(
                onPressed: _busy ? null : _submit,
                child: _busy
                    ? const SizedBox(
                        height: 22,
                        width: 22,
                        child: CircularProgressIndicator(
                          color: Colors.white,
                          strokeWidth: 2.4,
                        ),
                      )
                    : const Text('Importer'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// HomeScreen — balances + actions.
// ---------------------------------------------------------------------------

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  BigInt _usdt = BigInt.zero;
  BigInt _pol = BigInt.zero;
  bool _loading = true;
  String? _err;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    setState(() {
      _loading = true;
      _err = null;
    });
    try {
      final results = await Future.wait([
        WalletService.instance.usdtBalance(),
        WalletService.instance.polBalance(),
      ]);
      if (!mounted) return;
      setState(() {
        _usdt = results[0];
        _pol = results[1];
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _err = e.toString();
      });
    }
  }

  Future<void> _confirmWipe() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: kCard,
        title: const Text('Supprimer cette wallet ?',
            style: TextStyle(color: Colors.white)),
        content: const Text(
          "Sans la phrase de récupération, les fonds seront perdus. Confirmez-vous ?",
          style: TextStyle(color: kMuted),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Annuler'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Supprimer',
                style: TextStyle(color: Colors.redAccent)),
          ),
        ],
      ),
    );
    if (ok != true) return;
    await WalletService.instance.wipe();
    if (!mounted) return;
    Navigator.of(context).pushAndRemoveUntil(
      MaterialPageRoute(builder: (_) => const OnboardScreen()),
      (_) => false,
    );
  }

  @override
  Widget build(BuildContext context) {
    final addr = WalletService.instance.address?.hexEip55 ?? '';
    final usdtStr = WalletService.formatAmount(_usdt, kUsdtDecimals);
    final polStr = WalletService.formatAmount(_pol, 18, displayDp: 4);
    return Scaffold(
      appBar: AppBar(
        title: const Text('Tchipa Wallet'),
        actions: [
          IconButton(
            icon: const Icon(Icons.delete_outline),
            onPressed: _confirmWipe,
            tooltip: 'Supprimer la wallet',
          ),
        ],
      ),
      body: RefreshIndicator(
        color: kAccent,
        onRefresh: _refresh,
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            _addressCard(addr),
            const SizedBox(height: 16),
            _balanceCard(
              symbol: 'USDT',
              amount: usdtStr,
              sub: 'Tether (Polygon)',
              loading: _loading,
            ),
            const SizedBox(height: 12),
            _balanceCard(
              symbol: 'POL',
              amount: polStr,
              sub: 'Gas Polygon',
              loading: _loading,
            ),
            if (_err != null) ...[
              const SizedBox(height: 16),
              Text('Erreur: $_err',
                  style: const TextStyle(color: Colors.redAccent)),
            ],
            const SizedBox(height: 24),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton.icon(
                    icon: const Icon(Icons.arrow_upward),
                    label: const Text('Envoyer'),
                    onPressed: () async {
                      await Navigator.of(context).push(
                        MaterialPageRoute(builder: (_) => const SendScreen()),
                      );
                      _refresh();
                    },
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: OutlinedButton.icon(
                    icon: const Icon(Icons.arrow_downward),
                    label: const Text('Recevoir'),
                    onPressed: () => Navigator.of(context).push(
                      MaterialPageRoute(builder: (_) => const ReceiveScreen()),
                    ),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: Colors.white,
                      minimumSize: const Size.fromHeight(52),
                      side: const BorderSide(color: kMuted),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(14),
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _addressCard(String addr) {
    final short = addr.length > 12
        ? '${addr.substring(0, 8)}…${addr.substring(addr.length - 6)}'
        : addr;
    return GestureDetector(
      onTap: () async {
        await Clipboard.setData(ClipboardData(text: addr));
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Adresse copiée.')),
        );
      },
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: kCard,
          borderRadius: BorderRadius.circular(14),
        ),
        child: Row(
          children: [
            const Icon(Icons.account_balance_wallet, color: kAccent),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Adresse',
                      style: TextStyle(color: kMuted, fontSize: 12)),
                  const SizedBox(height: 2),
                  Text(short,
                      style: const TextStyle(
                          color: Colors.white,
                          fontFamily: 'monospace',
                          fontSize: 14)),
                ],
              ),
            ),
            const Icon(Icons.copy, color: kMuted, size: 18),
          ],
        ),
      ),
    );
  }

  Widget _balanceCard({
    required String symbol,
    required String amount,
    required String sub,
    required bool loading,
  }) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: kCard,
        borderRadius: BorderRadius.circular(14),
      ),
      child: Row(
        children: [
          Container(
            width: 44,
            height: 44,
            decoration: BoxDecoration(
              color: kBg,
              borderRadius: BorderRadius.circular(22),
            ),
            alignment: Alignment.center,
            child: Text(
              symbol.substring(0, 1),
              style: const TextStyle(
                  color: kAccent, fontWeight: FontWeight.w700, fontSize: 18),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(symbol,
                    style: const TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.w600,
                        fontSize: 16)),
                Text(sub, style: const TextStyle(color: kMuted, fontSize: 12)),
              ],
            ),
          ),
          loading
              ? const SizedBox(
                  height: 18,
                  width: 18,
                  child: CircularProgressIndicator(
                      strokeWidth: 2, color: kAccent),
                )
              : Text(amount,
                  style: const TextStyle(
                      color: Colors.white,
                      fontWeight: FontWeight.w700,
                      fontSize: 18)),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// ReceiveScreen — QR + copy address.
// ---------------------------------------------------------------------------

class ReceiveScreen extends StatelessWidget {
  const ReceiveScreen({super.key});
  @override
  Widget build(BuildContext context) {
    final addr = WalletService.instance.address?.hexEip55 ?? '';
    return Scaffold(
      appBar: AppBar(title: const Text('Recevoir')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            children: [
              const Text(
                "N'envoyez QUE de l'USDT ou du POL sur le réseau Polygon "
                "à cette adresse. Tout autre token ou réseau peut être perdu.",
                textAlign: TextAlign.center,
                style: TextStyle(color: kMuted, height: 1.4),
              ),
              const SizedBox(height: 24),
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(14),
                ),
                child: QrImageView(
                  data: addr,
                  size: 240,
                  backgroundColor: Colors.white,
                ),
              ),
              const SizedBox(height: 20),
              SelectableText(
                addr,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  color: Colors.white,
                  fontFamily: 'monospace',
                  fontSize: 13,
                ),
              ),
              const SizedBox(height: 20),
              ElevatedButton.icon(
                icon: const Icon(Icons.copy),
                label: const Text("Copier l'adresse"),
                onPressed: () async {
                  await Clipboard.setData(ClipboardData(text: addr));
                  if (!context.mounted) return;
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Adresse copiée.')),
                  );
                },
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// SendScreen — send USDT.
// ---------------------------------------------------------------------------

class SendScreen extends StatefulWidget {
  const SendScreen({super.key});
  @override
  State<SendScreen> createState() => _SendScreenState();
}

class _SendScreenState extends State<SendScreen> {
  final TextEditingController _toCtrl = TextEditingController();
  final TextEditingController _amtCtrl = TextEditingController();
  bool _sending = false;
  String? _err;

  @override
  void dispose() {
    _toCtrl.dispose();
    _amtCtrl.dispose();
    super.dispose();
  }

  Future<void> _send() async {
    setState(() {
      _sending = true;
      _err = null;
    });
    try {
      final to = _toCtrl.text.trim();
      EthereumAddress.fromHex(to); // validates
      final amount = WalletService.parseAmount(_amtCtrl.text, kUsdtDecimals);
      if (amount <= BigInt.zero) {
        throw const FormatException('Montant doit être > 0.');
      }
      final hash = await WalletService.instance.sendUsdt(
        toHex: to,
        amountWei: amount,
      );
      if (!mounted) return;
      Navigator.pop(context);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Transaction envoyée: ${hash.substring(0, 12)}…'),
          duration: const Duration(seconds: 6),
        ),
      );
    } catch (e) {
      setState(() {
        _sending = false;
        _err = e.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Envoyer USDT')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _field(
                controller: _toCtrl,
                label: 'Adresse destinataire',
                hint: '0x...',
              ),
              const SizedBox(height: 16),
              _field(
                controller: _amtCtrl,
                label: 'Montant (USDT)',
                hint: '0.00',
                keyboard: const TextInputType.numberWithOptions(decimal: true),
              ),
              if (_err != null) ...[
                const SizedBox(height: 12),
                Text(_err!, style: const TextStyle(color: Colors.redAccent)),
              ],
              const SizedBox(height: 12),
              const Text(
                "Note: les frais de gas sont payés en POL. Si votre solde POL "
                "est à 0, la transaction échouera.",
                style: TextStyle(color: kMuted, fontSize: 12, height: 1.4),
              ),
              const Spacer(),
              ElevatedButton(
                onPressed: _sending ? null : _send,
                child: _sending
                    ? const SizedBox(
                        height: 22,
                        width: 22,
                        child: CircularProgressIndicator(
                          color: Colors.white,
                          strokeWidth: 2.4,
                        ),
                      )
                    : const Text('Envoyer'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _field({
    required TextEditingController controller,
    required String label,
    required String hint,
    TextInputType? keyboard,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: const TextStyle(color: kMuted, fontSize: 12)),
        const SizedBox(height: 6),
        TextField(
          controller: controller,
          keyboardType: keyboard,
          style: const TextStyle(color: Colors.white),
          decoration: InputDecoration(
            filled: true,
            fillColor: kCard,
            hintText: hint,
            hintStyle: const TextStyle(color: kMuted),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(14),
              borderSide: BorderSide.none,
            ),
          ),
        ),
      ],
    );
  }
}

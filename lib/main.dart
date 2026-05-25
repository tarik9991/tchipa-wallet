// Tchipa Wallet — self-custody USDT/Polygon wallet.
//
// Single-file architecture, mirrors the convention of the main Tchipa app.
// Sections: constants, BioAuth, WalletService, shared UI (buttons, cards,
// PIN pad, spinning logo), then screens (Splash, Onboard, Create, Import,
// SetPin, Lock, Home, Receive, Send, Profile).

import 'dart:convert';
import 'dart:math' as math;

import 'package:bip32/bip32.dart' as bip32;
import 'package:bip39/bip39.dart' as bip39;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:local_auth/local_auth.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:web3dart/web3dart.dart';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Polygon RPC endpoints, tried in order with automatic fallback. The public
// `polygon-rpc.com` is unreliable — it intermittently returns non-JSON
// rate-limit pages that crash web3dart with
// "type 'String' is not a subtype of type 'int' of 'index'", so it is NOT used.
const List<String> kPolygonRpcs = [
  'https://polygon-bor-rpc.publicnode.com',
  'https://1rpc.io/matic',
  'https://polygon.drpc.org',
  'https://polygon.llamarpc.com',
];
const int kPolygonChainId = 137;

// Tchipa backend (shared with the VCC app). Hosts the gas-loan endpoint that
// drips a little POL to a USDT-funded wallet so it can pay gas; the app repays
// the value in USDT in the same send flow.
const String kApiBase = 'https://api.tchipa.co.uk';
// Below this POL balance a wallet "needs" a gas loan before it can send.
const double kGasThresholdPol = 0.02;

// USDT on Polygon (PoS), 6 decimals.
const String kUsdtAddress = '0xc2132D05D31c914a87C6611C10748AEb04B58e8F';
const int kUsdtDecimals = 6;

// BIP-44 path for Ethereum/EVM accounts.
const String kHdPath = "m/44'/60'/0'/0/0";

// Secure storage keys.
const String kStorageMnemonic = 'tchipa_wallet_mnemonic_v1';
const String kStoragePin = 'tchipa_wallet_pin_v1';
const String kStorageBio = 'tchipa_wallet_bio_v1';

// Minimal ERC-20 ABI (balanceOf, transfer).
const String kErc20Abi =
    '[{"constant":true,"inputs":[{"name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"type":"function"},'
    '{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"}]';

// ── Palette (Dark / OLED) ──────────────────────────────────────────────────
const Color kBg = Color(0xFF0B0E13);
const Color kCard = Color(0xFF161A23);
const Color kCardHi = Color(0xFF1E2330);
const Color kStroke = Color(0xFF262C3A);
const Color kAccent = Color(0xFF7C5CFF);
const Color kAccentDeep = Color(0xFF5B3FE0);
const Color kGold = Color(0xFFF5B544); // value / USDT trust accent
const Color kGreen = Color(0xFF35C28E);
const Color kRed = Color(0xFFFF5C6C);
const Color kMuted = Color(0xFF8A93A6);

const LinearGradient kAccentGrad = LinearGradient(
  begin: Alignment.topLeft,
  end: Alignment.bottomRight,
  colors: [kAccent, kAccentDeep],
);

// ---------------------------------------------------------------------------
// BioAuth — thin wrapper around local_auth.
// ---------------------------------------------------------------------------

class BioAuth {
  static final LocalAuthentication _auth = LocalAuthentication();

  static Future<bool> available() async {
    try {
      return await _auth.isDeviceSupported() &&
          await _auth.canCheckBiometrics;
    } catch (_) {
      return false;
    }
  }

  static Future<bool> authenticate(String reason) async {
    try {
      return await _auth.authenticate(
        localizedReason: reason,
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: true,
        ),
      );
    } catch (_) {
      return false;
    }
  }
}

// ---------------------------------------------------------------------------
// WalletService — holds the active EVM account, talks to Polygon.
// ---------------------------------------------------------------------------

class WalletService {
  WalletService._();
  static final WalletService instance = WalletService._();

  final FlutterSecureStorage _storage = const FlutterSecureStorage();

  // Index of the last RPC endpoint that worked — tried first next time.
  int _rpcIdx = 0;

  EthPrivateKey? _credentials;
  EthereumAddress? _address;
  String? _mnemonic;

  bool get isLoaded => _credentials != null;
  EthereumAddress? get address => _address;
  String? get mnemonic => _mnemonic;
  String get addressHex => _address?.hexEip55 ?? '';

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
    await _storage.delete(key: kStoragePin);
    await _storage.delete(key: kStorageBio);
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

  // ── PIN / biometric lock ──────────────────────────────────────────────
  Future<bool> hasPin() async =>
      (await _storage.read(key: kStoragePin))?.isNotEmpty ?? false;
  Future<void> setPin(String pin) => _storage.write(key: kStoragePin, value: pin);
  Future<bool> verifyPin(String pin) async =>
      (await _storage.read(key: kStoragePin)) == pin;
  Future<bool> bioEnabled() async =>
      (await _storage.read(key: kStorageBio)) == '1';
  Future<void> setBioEnabled(bool v) =>
      _storage.write(key: kStorageBio, value: v ? '1' : '0');

  // ── Chain reads / writes (with RPC fallback) ──────────────────────────
  Future<T> _rpc<T>(Future<T> Function(Web3Client) op) async {
    Object? lastErr;
    for (var i = 0; i < kPolygonRpcs.length; i++) {
      final idx = (_rpcIdx + i) % kPolygonRpcs.length;
      final client = Web3Client(kPolygonRpcs[idx], http.Client());
      try {
        final result = await op(client).timeout(const Duration(seconds: 15));
        _rpcIdx = idx; // remember the one that worked
        return result;
      } catch (e) {
        lastErr = e;
      } finally {
        client.dispose();
      }
    }
    throw lastErr ?? StateError('Tous les RPC Polygon ont échoué.');
  }

  Future<BigInt> polBalance() async {
    if (_address == null) return BigInt.zero;
    final v = await _rpc((c) => c.getBalance(_address!));
    return v.getInWei;
  }

  Future<BigInt> usdtBalance() async {
    if (_address == null) return BigInt.zero;
    final contract = _erc20();
    final fn = contract.function('balanceOf');
    final res = await _rpc(
      (c) => c.call(contract: contract, function: fn, params: [_address!]),
    );
    return res.first as BigInt;
  }

  Future<String> sendUsdt({
    required String toHex,
    required BigInt amountWei,
    int? nonce,
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
      nonce: nonce,
    );
    return _rpc(
      (c) => c.sendTransaction(_credentials!, tx, chainId: kPolygonChainId),
    );
  }

  // Next nonce for this wallet — used to order the user's send and the gas
  // repayment back-to-back without waiting for the first to be mined.
  Future<int> txCount() async =>
      _rpc((c) => c.getTransactionCount(_address!));

  // Asks the backend to drip POL for gas. Returns the parsed JSON; throws on
  // a non-200 with the server's error message.
  Future<Map<String, dynamic>> requestGasLoan() async {
    final resp = await http
        .post(
          Uri.parse('$kApiBase/gas/loan'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'address': addressHex}),
        )
        .timeout(const Duration(seconds: 30));
    final data = jsonDecode(resp.body) as Map<String, dynamic>;
    if (resp.statusCode != 200) {
      throw Exception(data['error'] ?? 'Échec du prêt de gas.');
    }
    return data;
  }

  // Polls until the POL balance reaches [minPol] or the timeout elapses.
  Future<void> waitForPol(
    double minPol, {
    Duration timeout = const Duration(seconds: 90),
  }) async {
    final target = parseAmount(minPol.toString(), 18);
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      if (await polBalance() >= target) return;
      await Future.delayed(const Duration(seconds: 4));
    }
    throw StateError('Le POL de gas n\'est pas arrivé à temps. Réessayez.');
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

  static String shortAddress(String addr) => addr.length > 12
      ? '${addr.substring(0, 6)}…${addr.substring(addr.length - 4)}'
      : addr;
}

// ---------------------------------------------------------------------------
// Shared UI
// ---------------------------------------------------------------------------

void showToast(BuildContext context, String msg) {
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(
      SnackBar(
        content: Text(msg),
        behavior: SnackBarBehavior.floating,
        backgroundColor: kCardHi,
        shape:
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        margin: const EdgeInsets.all(16),
      ),
    );
}

BoxDecoration cardDecoration({Color? color}) => BoxDecoration(
      color: color ?? kCard,
      borderRadius: BorderRadius.circular(18),
      border: Border.all(color: kStroke),
    );

// Primary CTA — gradient pill with optional busy spinner.
class PrimaryButton extends StatelessWidget {
  const PrimaryButton({
    super.key,
    required this.label,
    required this.onPressed,
    this.busy = false,
    this.icon,
  });
  final String label;
  final VoidCallback? onPressed;
  final bool busy;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final enabled = onPressed != null && !busy;
    return Opacity(
      opacity: enabled ? 1 : 0.5,
      child: DecoratedBox(
        decoration: BoxDecoration(
          gradient: kAccentGrad,
          borderRadius: BorderRadius.circular(16),
          boxShadow: enabled
              ? const [
                  BoxShadow(
                    color: Color(0x557C5CFF),
                    blurRadius: 22,
                    offset: Offset(0, 8),
                  ),
                ]
              : null,
        ),
        child: Material(
          color: Colors.transparent,
          child: InkWell(
            borderRadius: BorderRadius.circular(16),
            onTap: enabled ? onPressed : null,
            child: SizedBox(
              height: 56,
              child: Center(
                child: busy
                    ? const SizedBox(
                        height: 22,
                        width: 22,
                        child: CircularProgressIndicator(
                          color: Colors.white,
                          strokeWidth: 2.4,
                        ),
                      )
                    : Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          if (icon != null) ...[
                            Icon(icon, color: Colors.white, size: 20),
                            const SizedBox(width: 8),
                          ],
                          Text(
                            label,
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 16,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                        ],
                      ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class GhostButton extends StatelessWidget {
  const GhostButton({
    super.key,
    required this.label,
    required this.onPressed,
    this.icon,
  });
  final String label;
  final VoidCallback? onPressed;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      height: 56,
      child: OutlinedButton(
        onPressed: onPressed,
        style: OutlinedButton.styleFrom(
          foregroundColor: Colors.white,
          side: const BorderSide(color: kStroke),
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (icon != null) ...[
              Icon(icon, size: 20),
              const SizedBox(width: 8),
            ],
            Text(label,
                style:
                    const TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
          ],
        ),
      ),
    );
  }
}

// SpinningLogo — Tchipa "T" mark that pivots on its own vertical axis (rotateY
// with a touch of perspective): turns side-to-side like a coin, NOT a flip.
class SpinningLogo extends StatefulWidget {
  const SpinningLogo({super.key, this.size = 120});
  final double size;
  @override
  State<SpinningLogo> createState() => _SpinningLogoState();
}

class _SpinningLogoState extends State<SpinningLogo>
    with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 6),
    )..repeat();
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      width: widget.size,
      height: widget.size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        boxShadow: [
          BoxShadow(
              color: const Color(0x447C5CFF),
              blurRadius: widget.size * 0.36,
              spreadRadius: widget.size * 0.05),
        ],
      ),
      child: AnimatedBuilder(
        animation: _ctrl,
        builder: (_, child) {
          return Transform(
            alignment: Alignment.center,
            transform: Matrix4.identity()
              ..setEntry(3, 2, 0.0015) // subtle perspective
              ..rotateY(_ctrl.value * 2 * math.pi),
            child: child,
          );
        },
        child: Image.asset('assets/tchipa_logo.png', fit: BoxFit.contain),
      ),
    );
  }
}

// PIN dots indicator.
class PinDots extends StatelessWidget {
  const PinDots({super.key, required this.length, required this.filled});
  final int length;
  final int filled;
  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: List.generate(length, (i) {
        final on = i < filled;
        return AnimatedContainer(
          duration: const Duration(milliseconds: 150),
          margin: const EdgeInsets.symmetric(horizontal: 9),
          width: 16,
          height: 16,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: on ? kAccent : Colors.transparent,
            border: Border.all(color: on ? kAccent : kMuted, width: 1.6),
          ),
        );
      }),
    );
  }
}

// Numeric keypad with optional biometric key (bottom-left).
class PinKeypad extends StatelessWidget {
  const PinKeypad({
    super.key,
    required this.onDigit,
    required this.onBackspace,
    this.onBio,
  });
  final ValueChanged<String> onDigit;
  final VoidCallback onBackspace;
  final VoidCallback? onBio;

  @override
  Widget build(BuildContext context) {
    Widget key(Widget child, VoidCallback? onTap) => Material(
          color: Colors.transparent,
          child: InkResponse(
            onTap: onTap,
            radius: 44,
            child: SizedBox(height: 72, child: Center(child: child)),
          ),
        );
    Widget digit(String d) => key(
          Text(d,
              style: const TextStyle(
                  color: Colors.white,
                  fontSize: 28,
                  fontWeight: FontWeight.w600)),
          () => onDigit(d),
        );
    return Column(
      children: [
        Row(children: [
          Expanded(child: digit('1')),
          Expanded(child: digit('2')),
          Expanded(child: digit('3')),
        ]),
        Row(children: [
          Expanded(child: digit('4')),
          Expanded(child: digit('5')),
          Expanded(child: digit('6')),
        ]),
        Row(children: [
          Expanded(child: digit('7')),
          Expanded(child: digit('8')),
          Expanded(child: digit('9')),
        ]),
        Row(children: [
          Expanded(
            child: onBio != null
                ? key(const Icon(Icons.fingerprint, color: kAccent, size: 30),
                    onBio)
                : const SizedBox(height: 72),
          ),
          Expanded(child: digit('0')),
          Expanded(
            child: key(
              const Icon(Icons.backspace_outlined, color: kMuted, size: 24),
              onBackspace,
            ),
          ),
        ]),
      ],
    );
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
          surfaceTintColor: Colors.transparent,
          elevation: 0,
          centerTitle: true,
        ),
        snackBarTheme: const SnackBarThemeData(
          contentTextStyle: TextStyle(color: Colors.white),
        ),
      ),
      home: const SplashScreen(),
    );
  }
}

// ---------------------------------------------------------------------------
// SplashScreen — decide route based on stored wallet + lock state.
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
    if (has) await svc.loadFromStorage();
    final hasPin = has && await svc.hasPin();
    if (!mounted) return;
    Widget next;
    if (!has) {
      next = const OnboardScreen();
    } else if (hasPin) {
      next = const LockScreen();
    } else {
      next = const HomeScreen();
    }
    Navigator.of(context)
        .pushReplacement(MaterialPageRoute(builder: (_) => next));
  }

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      backgroundColor: kBg,
      body: Center(child: SpinningLogo(size: 96)),
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
          padding: const EdgeInsets.fromLTRB(24, 24, 24, 28),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const SizedBox(height: 36),
              const Center(child: SpinningLogo(size: 132)),
              const SizedBox(height: 32),
              const Text(
                'Tchipa Wallet',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 30,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 0.3,
                ),
              ),
              const SizedBox(height: 10),
              const Text(
                'Votre wallet USDT sur Polygon, en self-custody.\nVos clés, vos fonds — personne d\'autre.',
                textAlign: TextAlign.center,
                style: TextStyle(color: kMuted, fontSize: 14.5, height: 1.5),
              ),
              const SizedBox(height: 28),
              _bullet(Icons.lock_outline, 'Clés stockées chiffrées sur l\'appareil'),
              _bullet(Icons.bolt_outlined, 'Envoi & réception USDT en quelques secondes'),
              _bullet(Icons.fingerprint, 'Déverrouillage par empreinte ou code'),
              const Spacer(),
              PrimaryButton(
                label: 'Créer une nouvelle wallet',
                icon: Icons.add,
                onPressed: () => Navigator.of(context).push(
                  MaterialPageRoute(builder: (_) => const CreateWalletScreen()),
                ),
              ),
              const SizedBox(height: 12),
              GhostButton(
                label: 'Importer une phrase',
                icon: Icons.download_outlined,
                onPressed: () => Navigator.of(context).push(
                  MaterialPageRoute(builder: (_) => const ImportWalletScreen()),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _bullet(IconData icon, String text) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 7),
        child: Row(
          children: [
            Container(
              width: 38,
              height: 38,
              decoration: BoxDecoration(
                color: kCard,
                borderRadius: BorderRadius.circular(11),
                border: Border.all(color: kStroke),
              ),
              child: Icon(icon, color: kAccent, size: 19),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Text(text,
                  style: const TextStyle(color: Colors.white, fontSize: 14)),
            ),
          ],
        ),
      );
}

// ---------------------------------------------------------------------------
// CreateWalletScreen — show 12 words, force confirmation, then set a PIN.
// ---------------------------------------------------------------------------

class CreateWalletScreen extends StatefulWidget {
  // replace: regenerating an existing wallet (compromised seed). Keeps the
  // current PIN and returns to Home instead of running PIN onboarding.
  const CreateWalletScreen({super.key, this.replace = false});
  final bool replace;
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
      if (widget.replace) {
        // Seed swapped in place; existing PIN still guards the app.
        showToast(context, 'Nouvelle wallet active.');
        Navigator.of(context).pushAndRemoveUntil(
          MaterialPageRoute(builder: (_) => const HomeScreen()),
          (_) => false,
        );
      } else {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (_) => const SetPinScreen()),
        );
      }
    } catch (e) {
      setState(() => _saving = false);
      if (!mounted) return;
      showToast(context, 'Erreur: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    final words = _mnemonic.split(' ');
    return Scaffold(
      appBar: AppBar(title: const Text('Phrase de récupération')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(24, 8, 24, 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: kGold.withValues(alpha: 0.10),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: kGold.withValues(alpha: 0.3)),
                ),
                child: const Row(
                  children: [
                    Icon(Icons.warning_amber_rounded, color: kGold, size: 22),
                    SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        'Notez ces 12 mots dans l\'ordre, hors-ligne. '
                        'Qui les détient contrôle vos fonds. Tchipa ne peut PAS les récupérer.',
                        style: TextStyle(color: Colors.white, fontSize: 12.5, height: 1.4),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 18),
              Expanded(
                child: SingleChildScrollView(
                  child: Stack(
                    children: [
                      GridView.builder(
                        shrinkWrap: true,
                        physics: const NeverScrollableScrollPhysics(),
                        gridDelegate:
                            const SliverGridDelegateWithFixedCrossAxisCount(
                          crossAxisCount: 2,
                          childAspectRatio: 3.2,
                          crossAxisSpacing: 12,
                          mainAxisSpacing: 12,
                        ),
                        itemCount: 12,
                        itemBuilder: (_, i) => Container(
                          padding: const EdgeInsets.symmetric(horizontal: 14),
                          alignment: Alignment.centerLeft,
                          decoration: cardDecoration(),
                          child: Row(
                            children: [
                              Text('${i + 1}',
                                  style: const TextStyle(
                                      color: kMuted,
                                      fontSize: 12,
                                      fontWeight: FontWeight.w600)),
                              const SizedBox(width: 10),
                              Text(words[i],
                                  style: const TextStyle(
                                      color: Colors.white,
                                      fontSize: 15,
                                      fontWeight: FontWeight.w600)),
                            ],
                          ),
                        ),
                      ),
                      if (!_revealed)
                        Positioned.fill(
                          child: ClipRRect(
                            borderRadius: BorderRadius.circular(18),
                            child: GestureDetector(
                              onTap: () => setState(() => _revealed = true),
                              child: Container(
                                color: kBg.withValues(alpha: 0.86),
                                alignment: Alignment.center,
                                child: const Column(
                                  mainAxisSize: MainAxisSize.min,
                                  children: [
                                    Icon(Icons.visibility_off_outlined,
                                        color: kAccent, size: 34),
                                    SizedBox(height: 10),
                                    Text('Toucher pour révéler',
                                        style: TextStyle(
                                            color: Colors.white,
                                            fontWeight: FontWeight.w600)),
                                  ],
                                ),
                              ),
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 12),
              if (_revealed)
                TextButton.icon(
                  onPressed: () async {
                    await Clipboard.setData(ClipboardData(text: _mnemonic));
                    if (!context.mounted) return;
                    showToast(context, 'Phrase copiée.');
                  },
                  icon: const Icon(Icons.copy, size: 16, color: kMuted),
                  label: const Text('Copier la phrase',
                      style: TextStyle(color: kMuted)),
                ),
              const SizedBox(height: 8),
              PrimaryButton(
                label: 'J\'ai noté la phrase, continuer',
                busy: _saving,
                onPressed: _revealed ? _confirm : null,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// ImportWalletScreen — paste an existing mnemonic, then set a PIN.
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
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (_) => const SetPinScreen()),
      );
    } catch (e) {
      setState(() {
        _busy = false;
        _err = e.toString().replaceFirst('FormatException: ', '');
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Importer une wallet')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(24, 8, 24, 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'Collez votre phrase de 12 ou 24 mots, séparés par des espaces.',
                style: TextStyle(color: kMuted, height: 1.5, fontSize: 14),
              ),
              const SizedBox(height: 18),
              Container(
                decoration: cardDecoration(),
                child: TextField(
                  controller: _ctrl,
                  maxLines: 4,
                  style: const TextStyle(color: Colors.white, fontSize: 15),
                  decoration: InputDecoration(
                    contentPadding: const EdgeInsets.all(16),
                    hintText: 'word1 word2 word3 …',
                    hintStyle: const TextStyle(color: kMuted),
                    border: InputBorder.none,
                    errorText: _err,
                  ),
                ),
              ),
              const Spacer(),
              PrimaryButton(
                label: 'Importer',
                busy: _busy,
                onPressed: _submit,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// SetPinScreen — choose a 6-digit PIN (enter + confirm), then offer biometrics.
// ---------------------------------------------------------------------------

class SetPinScreen extends StatefulWidget {
  const SetPinScreen({super.key, this.asChange = false});

  /// When true, this is a "change PIN" flow reached from Profile — it pops back
  /// instead of routing to Home.
  final bool asChange;

  @override
  State<SetPinScreen> createState() => _SetPinScreenState();
}

class _SetPinScreenState extends State<SetPinScreen> {
  String _first = '';
  String _entry = '';
  bool _confirming = false;
  String? _err;

  void _onDigit(String d) {
    if (_entry.length >= 6) return;
    setState(() {
      _entry += d;
      _err = null;
    });
    if (_entry.length == 6) _advance();
  }

  void _onBackspace() {
    if (_entry.isEmpty) return;
    setState(() => _entry = _entry.substring(0, _entry.length - 1));
  }

  Future<void> _advance() async {
    if (!_confirming) {
      setState(() {
        _first = _entry;
        _entry = '';
        _confirming = true;
      });
      return;
    }
    if (_entry != _first) {
      setState(() {
        _err = 'Les codes ne correspondent pas.';
        _entry = '';
        _first = '';
        _confirming = false;
      });
      return;
    }
    await WalletService.instance.setPin(_entry);
    if (!mounted) return;
    await _offerBiometric();
  }

  Future<void> _offerBiometric() async {
    final canBio = await BioAuth.available();
    if (canBio && mounted) {
      final enable = await showDialog<bool>(
        context: context,
        builder: (_) => AlertDialog(
          backgroundColor: kCard,
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
          title: const Text('Déverrouillage biométrique',
              style: TextStyle(color: Colors.white)),
          content: const Text(
            'Activer le déverrouillage par empreinte / visage ?',
            style: TextStyle(color: kMuted),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Plus tard', style: TextStyle(color: kMuted)),
            ),
            TextButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Activer',
                  style: TextStyle(
                      color: kAccent, fontWeight: FontWeight.w600)),
            ),
          ],
        ),
      );
      if (enable == true) {
        final ok = await BioAuth.authenticate('Confirmer la biométrie');
        await WalletService.instance.setBioEnabled(ok);
      }
    }
    if (!mounted) return;
    if (widget.asChange) {
      Navigator.pop(context);
      showToast(context, 'Code mis à jour.');
    } else {
      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const HomeScreen()),
        (_) => false,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: widget.asChange ? AppBar(title: const Text('Changer le code')) : null,
      body: SafeArea(
        child: Column(
          children: [
            const Spacer(flex: 2),
            Icon(_confirming ? Icons.lock_outline : Icons.pin_outlined,
                color: kAccent, size: 36),
            const SizedBox(height: 18),
            Text(
              _confirming ? 'Confirmez votre code' : 'Créez un code à 6 chiffres',
              style: const TextStyle(
                  color: Colors.white,
                  fontSize: 19,
                  fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 10),
            Text(
              _err ?? 'Il protège l\'accès à votre wallet.',
              style: TextStyle(
                  color: _err != null ? kRed : kMuted, fontSize: 13),
            ),
            const SizedBox(height: 28),
            PinDots(length: 6, filled: _entry.length),
            const Spacer(flex: 3),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 36),
              child: PinKeypad(onDigit: _onDigit, onBackspace: _onBackspace),
            ),
            const SizedBox(height: 12),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// LockScreen — unlock with biometrics or PIN. Reused for re-auth (verifyOnly).
// ---------------------------------------------------------------------------

class LockScreen extends StatefulWidget {
  const LockScreen({super.key, this.verifyOnly = false});

  /// When true, returns `true` via Navigator.pop on success instead of routing
  /// to Home — used to gate sensitive actions (revealing the recovery phrase).
  final bool verifyOnly;

  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  String _entry = '';
  String? _err;
  bool _bioAvailable = false;

  @override
  void initState() {
    super.initState();
    _initBio();
  }

  Future<void> _initBio() async {
    final enabled = await WalletService.instance.bioEnabled();
    final avail = enabled && await BioAuth.available();
    if (!mounted) return;
    setState(() => _bioAvailable = avail);
    if (avail) {
      WidgetsBinding.instance.addPostFrameCallback((_) => _tryBio());
    }
  }

  Future<void> _tryBio() async {
    final ok = await BioAuth.authenticate('Déverrouiller Tchipa Wallet');
    if (ok) _success();
  }

  void _onDigit(String d) {
    if (_entry.length >= 6) return;
    setState(() {
      _entry += d;
      _err = null;
    });
    if (_entry.length == 6) _check();
  }

  void _onBackspace() {
    if (_entry.isEmpty) return;
    setState(() => _entry = _entry.substring(0, _entry.length - 1));
  }

  Future<void> _check() async {
    final ok = await WalletService.instance.verifyPin(_entry);
    if (ok) {
      _success();
    } else {
      setState(() {
        _err = 'Code incorrect.';
        _entry = '';
      });
    }
  }

  void _success() {
    if (!mounted) return;
    if (widget.verifyOnly) {
      Navigator.pop(context, true);
    } else {
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (_) => const HomeScreen()),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: widget.verifyOnly
          ? AppBar(title: const Text('Confirmer l\'identité'))
          : null,
      body: SafeArea(
        child: Column(
          children: [
            const Spacer(flex: 2),
            const SpinningLogo(size: 84),
            const SizedBox(height: 24),
            Text(
              widget.verifyOnly ? 'Entrez votre code' : 'Bon retour',
              style: const TextStyle(
                  color: Colors.white,
                  fontSize: 20,
                  fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 8),
            Text(
              _err ?? 'Déverrouillez votre wallet',
              style: TextStyle(
                  color: _err != null ? kRed : kMuted, fontSize: 13),
            ),
            const SizedBox(height: 28),
            PinDots(length: 6, filled: _entry.length),
            const Spacer(flex: 3),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 36),
              child: PinKeypad(
                onDigit: _onDigit,
                onBackspace: _onBackspace,
                onBio: _bioAvailable ? _tryBio : null,
              ),
            ),
            const SizedBox(height: 12),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// HomeScreen — balance hero + assets + actions.
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
  List<Map<String, dynamic>> _rates = [];
  String? _ratesDate;

  @override
  void initState() {
    super.initState();
    _refresh();
    _loadRates();
  }

  // Parallel-market rates from the backend (scraped from squareportsaid.com).
  // Independent of balances: a failure here just hides the card.
  Future<void> _loadRates() async {
    try {
      final resp = await http
          .get(Uri.parse('$kApiBase/rates'))
          .timeout(const Duration(seconds: 15));
      if (resp.statusCode != 200) return;
      final j = jsonDecode(resp.body) as Map<String, dynamic>;
      if (!mounted) return;
      setState(() {
        _rates = (j['rates'] as List).cast<Map<String, dynamic>>();
        _ratesDate = j['date'] as String?;
      });
    } catch (_) {/* leave the card hidden */}
  }

  Future<void> _refresh() async {
    setState(() {
      _loading = true;
      _err = null;
    });
    _loadRates();
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
        _err = 'Réseau indisponible. Tirez pour réessayer.';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final addr = WalletService.instance.addressHex;
    final usdtStr = WalletService.formatAmount(_usdt, kUsdtDecimals, displayDp: 2);
    final polStr = WalletService.formatAmount(_pol, 18, displayDp: 4);
    return Scaffold(
      appBar: AppBar(
        titleSpacing: 16,
        title: Row(
          children: [
            const SpinningLogo(size: 34),
            const SizedBox(width: 10),
            const Text('Tchipa',
                style: TextStyle(fontWeight: FontWeight.w800, fontSize: 20)),
            Text(' Wallet',
                style: TextStyle(
                    fontWeight: FontWeight.w300,
                    fontSize: 20,
                    color: kMuted.withValues(alpha: 0.9))),
          ],
        ),
        centerTitle: false,
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 14),
            child: GestureDetector(
              onTap: () async {
                await Navigator.of(context).push(MaterialPageRoute(
                    builder: (_) => const ProfileScreen()));
                if (mounted) _refresh();
              },
              child: Container(
                width: 40,
                height: 40,
                decoration: BoxDecoration(
                  color: kCard,
                  shape: BoxShape.circle,
                  border: Border.all(color: kStroke),
                ),
                child: const Icon(Icons.person_outline,
                    color: Colors.white, size: 22),
              ),
            ),
          ),
        ],
      ),
      body: RefreshIndicator(
        color: kAccent,
        backgroundColor: kCard,
        onRefresh: _refresh,
        child: ListView(
          padding: const EdgeInsets.fromLTRB(20, 8, 20, 28),
          children: [
            _heroCard(usdtStr, addr),
            if (_err != null) ...[
              const SizedBox(height: 14),
              Row(
                children: [
                  const Icon(Icons.cloud_off, color: kMuted, size: 16),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(_err!,
                        style: const TextStyle(color: kMuted, fontSize: 12.5)),
                  ),
                ],
              ),
            ],
            const SizedBox(height: 20),
            _actions(),
            if (_rates.isNotEmpty) ...[
              const SizedBox(height: 26),
              _ratesCard(),
            ],
            const SizedBox(height: 26),
            const Text('Actifs',
                style: TextStyle(
                    color: kMuted,
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                    letterSpacing: 0.5)),
            const SizedBox(height: 12),
            _assetTile(
                symbol: 'USDT',
                name: 'Tether USD',
                amount: usdtStr,
                color: kGreen),
            const SizedBox(height: 10),
            _assetTile(
                symbol: 'POL',
                name: 'Polygon · Gas',
                amount: polStr,
                color: kAccent),
          ],
        ),
      ),
    );
  }

  Widget _heroCard(String usdtStr, String addr) {
    return Container(
      padding: const EdgeInsets.all(22),
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Color(0xFF2A2150), Color(0xFF161A23)],
        ),
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: kAccent.withValues(alpha: 0.25)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('Solde total',
              style: TextStyle(color: kMuted, fontSize: 13)),
          const SizedBox(height: 10),
          _loading
              ? const Padding(
                  padding: EdgeInsets.symmetric(vertical: 6),
                  child: SizedBox(
                    height: 30,
                    width: 30,
                    child: CircularProgressIndicator(
                        color: kAccent, strokeWidth: 2.4),
                  ),
                )
              : Row(
                  crossAxisAlignment: CrossAxisAlignment.baseline,
                  textBaseline: TextBaseline.alphabetic,
                  children: [
                    Text(usdtStr,
                        style: const TextStyle(
                            color: Colors.white,
                            fontSize: 40,
                            fontWeight: FontWeight.w800,
                            letterSpacing: -0.5)),
                    const SizedBox(width: 8),
                    const Padding(
                      padding: EdgeInsets.only(bottom: 6),
                      child: Text('USDT',
                          style: TextStyle(
                              color: kMuted,
                              fontSize: 16,
                              fontWeight: FontWeight.w600)),
                    ),
                  ],
                ),
          const SizedBox(height: 16),
          GestureDetector(
            onTap: () async {
              await Clipboard.setData(ClipboardData(text: addr));
              if (!mounted) return;
              showToast(context, 'Adresse copiée.');
            },
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                color: Colors.black.withValues(alpha: 0.25),
                borderRadius: BorderRadius.circular(30),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(Icons.account_balance_wallet_outlined,
                      color: kAccent, size: 16),
                  const SizedBox(width: 8),
                  Text(WalletService.shortAddress(addr),
                      style: const TextStyle(
                          color: Colors.white,
                          fontFamily: 'monospace',
                          fontSize: 13)),
                  const SizedBox(width: 8),
                  const Icon(Icons.copy, color: kMuted, size: 14),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  static String _fmtRate(dynamic n) {
    final d = (n as num).toDouble();
    return d == d.roundToDouble()
        ? d.toStringAsFixed(0)
        : d.toString();
  }

  Widget _ratesCard() {
    final usdt = _rates.firstWhere((r) => r['code'] == 'USDT',
        orElse: () => const {});
    final others = _rates.where((r) => r['code'] != 'USDT').toList();
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: cardDecoration(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Text('Taux du Square',
                  style: TextStyle(
                      color: Colors.white,
                      fontSize: 15,
                      fontWeight: FontWeight.w700)),
              const Spacer(),
              if (_ratesDate != null)
                Text(_ratesDate!,
                    style: const TextStyle(color: kMuted, fontSize: 11)),
            ],
          ),
          const SizedBox(height: 14),
          if (usdt.isNotEmpty) _usdtFeature(usdt),
          if (others.isNotEmpty) ...[
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: others.map(_rateChip).toList(),
            ),
          ],
          const SizedBox(height: 12),
          const Text('Marché parallèle · squareportsaid.com',
              style: TextStyle(color: kMuted, fontSize: 10.5)),
        ],
      ),
    );
  }

  // USDT shown first and biggest — it's what the wallet holds.
  Widget _usdtFeature(Map<String, dynamic> r) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        gradient: LinearGradient(colors: [
          kGreen.withValues(alpha: 0.16),
          kGreen.withValues(alpha: 0.04),
        ]),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: kGreen.withValues(alpha: 0.3)),
      ),
      child: Row(
        children: [
          Container(
            width: 46,
            height: 46,
            alignment: Alignment.center,
            decoration: const BoxDecoration(
                color: Color(0xFF26A17B), shape: BoxShape.circle),
            child: const Text('₮',
                style: TextStyle(
                    color: Colors.white,
                    fontSize: 24,
                    fontWeight: FontWeight.w800)),
          ),
          const SizedBox(width: 14),
          const Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('USDT',
                  style: TextStyle(
                      color: Colors.white,
                      fontSize: 18,
                      fontWeight: FontWeight.w800)),
              Text('Tether · DZD',
                  style: TextStyle(color: kMuted, fontSize: 12)),
            ],
          ),
          const Spacer(),
          Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Text(_fmtRate(r['buy']),
                  style: const TextStyle(
                      color: Colors.white,
                      fontSize: 30,
                      fontWeight: FontWeight.w900,
                      height: 1)),
              const SizedBox(height: 2),
              Text('Achat · Vente ${_fmtRate(r['sell'])}',
                  style: const TextStyle(color: kMuted, fontSize: 11.5)),
            ],
          ),
        ],
      ),
    );
  }

  Widget _rateChip(Map<String, dynamic> r) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: kBg.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: kStroke),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(r['code'] as String,
              style: const TextStyle(
                  color: Colors.white,
                  fontSize: 13,
                  fontWeight: FontWeight.w700)),
          const SizedBox(width: 8),
          Text('${_fmtRate(r['buy'])} / ${_fmtRate(r['sell'])}',
              style: const TextStyle(color: kMuted, fontSize: 12.5)),
        ],
      ),
    );
  }

  Widget _actions() {
    Widget item(IconData icon, String label, VoidCallback onTap) => Expanded(
          child: GestureDetector(
            onTap: onTap,
            child: Container(
              padding: const EdgeInsets.symmetric(vertical: 16),
              decoration: cardDecoration(),
              child: Column(
                children: [
                  Container(
                    width: 44,
                    height: 44,
                    decoration: const BoxDecoration(
                        gradient: kAccentGrad, shape: BoxShape.circle),
                    child: Icon(icon, color: Colors.white, size: 22),
                  ),
                  const SizedBox(height: 10),
                  Text(label,
                      style: const TextStyle(
                          color: Colors.white,
                          fontSize: 14,
                          fontWeight: FontWeight.w600)),
                ],
              ),
            ),
          ),
        );
    return Row(
      children: [
        item(Icons.arrow_upward, 'Envoyer', () async {
          await Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const SendScreen()));
          _refresh();
        }),
        const SizedBox(width: 12),
        item(Icons.arrow_downward, 'Recevoir', () {
          Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const ReceiveScreen()));
        }),
      ],
    );
  }

  Widget _assetTile({
    required String symbol,
    required String name,
    required String amount,
    required Color color,
  }) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: cardDecoration(),
      child: Row(
        children: [
          Container(
            width: 44,
            height: 44,
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(13),
            ),
            alignment: Alignment.center,
            child: Text(symbol.substring(0, 1),
                style: TextStyle(
                    color: color, fontWeight: FontWeight.w800, fontSize: 18)),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(symbol,
                    style: const TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.w700,
                        fontSize: 15)),
                Text(name,
                    style: const TextStyle(color: kMuted, fontSize: 12)),
              ],
            ),
          ),
          _loading
              ? const SizedBox(
                  height: 16,
                  width: 16,
                  child:
                      CircularProgressIndicator(strokeWidth: 2, color: kAccent),
                )
              : Text(amount,
                  style: const TextStyle(
                      color: Colors.white,
                      fontWeight: FontWeight.w700,
                      fontSize: 16)),
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
    final addr = WalletService.instance.addressHex;
    return Scaffold(
      appBar: AppBar(title: const Text('Recevoir')),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            children: [
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: kGold.withValues(alpha: 0.10),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: kGold.withValues(alpha: 0.3)),
                ),
                child: const Row(
                  children: [
                    Icon(Icons.info_outline, color: kGold, size: 20),
                    SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        'Envoyez uniquement de l\'USDT ou du POL sur le réseau '
                        'Polygon. Tout autre réseau / token sera perdu.',
                        style: TextStyle(
                            color: Colors.white, fontSize: 12.5, height: 1.4),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 28),
              Container(
                padding: const EdgeInsets.all(18),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(20),
                ),
                child: QrImageView(
                  data: addr,
                  size: 230,
                  backgroundColor: Colors.white,
                ),
              ),
              const SizedBox(height: 24),
              Container(
                padding: const EdgeInsets.all(16),
                decoration: cardDecoration(),
                child: SelectableText(
                  addr,
                  textAlign: TextAlign.center,
                  style: const TextStyle(
                    color: Colors.white,
                    fontFamily: 'monospace',
                    fontSize: 13,
                    height: 1.4,
                  ),
                ),
              ),
              const SizedBox(height: 20),
              PrimaryButton(
                label: 'Copier l\'adresse',
                icon: Icons.copy,
                onPressed: () async {
                  await Clipboard.setData(ClipboardData(text: addr));
                  if (!context.mounted) return;
                  showToast(context, 'Adresse copiée.');
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
  String? _status;

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
      _status = null;
    });
    try {
      final to = _toCtrl.text.trim();
      EthereumAddress.fromHex(to); // validates
      final amount = WalletService.parseAmount(_amtCtrl.text, kUsdtDecimals);
      if (amount <= BigInt.zero) {
        throw const FormatException('Le montant doit être supérieur à 0.');
      }
      final svc = WalletService.instance;

      // Gas check: an ERC-20 transfer needs POL. If the wallet has none, ask
      // the backend to drip a little, then repay its value in USDT.
      final polWei = await svc.polBalance();
      final polThreshold =
          WalletService.parseAmount(kGasThresholdPol.toString(), 18);

      String? repayTo;
      BigInt feeWei = BigInt.zero;
      bool loaned = false;

      if (polWei < polThreshold) {
        setState(() => _status = 'Pas de POL pour le gas — Tchipa l\'avance…');
        final loan = await svc.requestGasLoan();
        if (loan['funded'] == true) {
          loaned = true;
          feeWei = WalletService.parseAmount(
              loan['feeUsdt'].toString(), kUsdtDecimals);
          repayTo = loan['repayTo'] as String?;
          final usdtWei = await svc.usdtBalance();
          if (usdtWei < amount + feeWei) {
            throw Exception(
                'Solde USDT insuffisant : il faut couvrir le montant + ${loan['feeUsdt']} USDT de frais de gas.');
          }
          setState(() => _status = 'Réception du POL de gas…');
          await svc.waitForPol(kGasThresholdPol);
        }
      }

      // Order the two transfers with explicit nonces so they don't collide.
      final nonce = await svc.txCount();
      setState(() => _status = 'Envoi de la transaction…');
      final hash =
          await svc.sendUsdt(toHex: to, amountWei: amount, nonce: nonce);

      if (loaned && repayTo != null && feeWei > BigInt.zero) {
        setState(() => _status = 'Remboursement du gas…');
        try {
          await svc.sendUsdt(
              toHex: repayTo, amountWei: feeWei, nonce: nonce + 1);
        } catch (_) {
          // Best-effort: the user's transfer already went through.
        }
      }

      if (!mounted) return;
      Navigator.pop(context);
      showToast(context, 'Transaction envoyée : ${hash.substring(0, 14)}…');
    } catch (e) {
      setState(() {
        _sending = false;
        _status = null;
        _err = e
            .toString()
            .replaceFirst('FormatException: ', '')
            .replaceFirst('Exception: ', '');
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Envoyer USDT')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(24, 8, 24, 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _field(
                controller: _toCtrl,
                label: 'Adresse destinataire',
                hint: '0x…',
              ),
              const SizedBox(height: 18),
              _field(
                controller: _amtCtrl,
                label: 'Montant (USDT)',
                hint: '0.00',
                keyboard:
                    const TextInputType.numberWithOptions(decimal: true),
              ),
              if (_err != null) ...[
                const SizedBox(height: 14),
                Row(
                  children: [
                    const Icon(Icons.error_outline, color: kRed, size: 16),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(_err!,
                          style: const TextStyle(color: kRed, fontSize: 13)),
                    ),
                  ],
                ),
              ],
              const SizedBox(height: 18),
              Container(
                padding: const EdgeInsets.all(14),
                decoration: cardDecoration(color: kCardHi),
                child: const Row(
                  children: [
                    Icon(Icons.local_gas_station_outlined,
                        color: kMuted, size: 18),
                    SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        'Le gas se paie en POL. Si vous n\'en avez pas, Tchipa '
                        'l\'avance et prélève 0.40 USDT de frais.',
                        style: TextStyle(
                            color: kMuted, fontSize: 12.5, height: 1.4),
                      ),
                    ),
                  ],
                ),
              ),
              const Spacer(),
              if (_status != null) ...[
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    const SizedBox(
                      height: 14,
                      width: 14,
                      child: CircularProgressIndicator(
                          strokeWidth: 2, color: kAccent),
                    ),
                    const SizedBox(width: 10),
                    Text(_status!,
                        style: const TextStyle(color: kMuted, fontSize: 13)),
                  ],
                ),
                const SizedBox(height: 12),
              ],
              PrimaryButton(
                label: 'Envoyer',
                icon: Icons.arrow_upward,
                busy: _sending,
                onPressed: _sending ? null : _send,
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
        Text(label,
            style: const TextStyle(
                color: kMuted, fontSize: 13, fontWeight: FontWeight.w600)),
        const SizedBox(height: 8),
        Container(
          decoration: cardDecoration(),
          child: TextField(
            controller: controller,
            keyboardType: keyboard,
            style: const TextStyle(color: Colors.white, fontSize: 15),
            decoration: InputDecoration(
              contentPadding:
                  const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
              hintText: hint,
              hintStyle: const TextStyle(color: kMuted),
              border: InputBorder.none,
            ),
          ),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// ProfileScreen — address, recovery phrase, security, delete.
// ---------------------------------------------------------------------------

class ProfileScreen extends StatefulWidget {
  const ProfileScreen({super.key});
  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  bool _bio = false;
  bool _bioAvailable = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final bio = await WalletService.instance.bioEnabled();
    final avail = await BioAuth.available();
    if (!mounted) return;
    setState(() {
      _bio = bio;
      _bioAvailable = avail;
    });
  }

  Future<bool> _reauth() async {
    final ok = await Navigator.of(context).push<bool>(
      MaterialPageRoute(builder: (_) => const LockScreen(verifyOnly: true)),
    );
    return ok == true;
  }

  Future<void> _revealPhrase() async {
    final ok = await _reauth();
    if (ok && mounted) {
      Navigator.of(context).push(
        MaterialPageRoute(builder: (_) => const RecoveryPhraseScreen()),
      );
    }
  }

  Future<void> _toggleBio(bool v) async {
    if (v) {
      final ok = await BioAuth.authenticate('Activer la biométrie');
      if (!ok) return;
    }
    await WalletService.instance.setBioEnabled(v);
    if (!mounted) return;
    setState(() => _bio = v);
  }

  // Compromised seed → mint a fresh wallet. Keeps the current PIN; the old
  // address stays valid on-chain, so funds must be moved off it beforehand.
  Future<void> _regenerate() async {
    final authed = await _reauth();
    if (!authed || !mounted) return;
    final go = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: kCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
        title: const Text('Régénérer la wallet ?',
            style: TextStyle(color: Colors.white)),
        content: const Text(
          'Une nouvelle phrase de récupération et une nouvelle adresse seront '
          'créées. L\'ancienne adresse reste valable sur la blockchain : si elle '
          'est compromise, transférez d\'abord vos fonds, sinon ils y resteront. '
          'Action irréversible.',
          style: TextStyle(color: kMuted, height: 1.4),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Annuler', style: TextStyle(color: kMuted)),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Continuer', style: TextStyle(color: kGold)),
          ),
        ],
      ),
    );
    if (go != true || !mounted) return;
    Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const CreateWalletScreen(replace: true)),
    );
  }

  Future<void> _delete() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: kCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
        title: const Text('Supprimer cette wallet ?',
            style: TextStyle(color: Colors.white)),
        content: const Text(
          'Sans votre phrase de récupération, les fonds seront définitivement perdus.',
          style: TextStyle(color: kMuted, height: 1.4),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Annuler', style: TextStyle(color: kMuted)),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Supprimer', style: TextStyle(color: kRed)),
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
    final addr = WalletService.instance.addressHex;
    return Scaffold(
      appBar: AppBar(title: const Text('Profil')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            Center(
              child: Column(
                children: [
                  Container(
                    width: 72,
                    height: 72,
                    decoration: const BoxDecoration(
                        gradient: kAccentGrad, shape: BoxShape.circle),
                    child: const Icon(Icons.person,
                        color: Colors.white, size: 36),
                  ),
                  const SizedBox(height: 12),
                  GestureDetector(
                    onTap: () async {
                      await Clipboard.setData(ClipboardData(text: addr));
                      if (!context.mounted) return;
                      showToast(context, 'Adresse copiée.');
                    },
                    child: Text(WalletService.shortAddress(addr),
                        style: const TextStyle(
                            color: Colors.white,
                            fontFamily: 'monospace',
                            fontSize: 15,
                            fontWeight: FontWeight.w600)),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 28),
            _section('Wallet'),
            _tile(
              icon: Icons.qr_code,
              title: 'Adresse de réception',
              onTap: () => Navigator.of(context).push(
                  MaterialPageRoute(builder: (_) => const ReceiveScreen())),
            ),
            _tile(
              icon: Icons.vpn_key_outlined,
              title: 'Phrase de récupération',
              subtitle: 'Affichée après vérification',
              onTap: _revealPhrase,
            ),
            const SizedBox(height: 20),
            _section('Sécurité'),
            _switchTile(
              icon: Icons.fingerprint,
              title: 'Déverrouillage biométrique',
              value: _bio,
              enabled: _bioAvailable,
              onChanged: _toggleBio,
            ),
            _tile(
              icon: Icons.password_outlined,
              title: 'Changer le code',
              onTap: () => Navigator.of(context).push(MaterialPageRoute(
                  builder: (_) => const SetPinScreen(asChange: true))),
            ),
            _tile(
              icon: Icons.autorenew,
              title: 'Régénérer la wallet',
              subtitle: 'Nouveau seed en cas de compromission',
              onTap: _regenerate,
            ),
            const SizedBox(height: 20),
            _section('Réseau'),
            _tile(
              icon: Icons.hub_outlined,
              title: 'Polygon',
              subtitle: 'USDT (PoS) · gas en POL',
              trailing: Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: kGreen.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: const Text('Connecté',
                    style: TextStyle(
                        color: kGreen,
                        fontSize: 11,
                        fontWeight: FontWeight.w600)),
              ),
            ),
            const SizedBox(height: 28),
            _tile(
              icon: Icons.delete_outline,
              title: 'Supprimer la wallet',
              danger: true,
              onTap: _delete,
            ),
            const SizedBox(height: 24),
            const Center(
              child: Text('Tchipa Wallet · self-custody',
                  style: TextStyle(color: kMuted, fontSize: 12)),
            ),
          ],
        ),
      ),
    );
  }

  Widget _section(String t) => Padding(
        padding: const EdgeInsets.only(left: 4, bottom: 10),
        child: Text(t,
            style: const TextStyle(
                color: kMuted,
                fontSize: 13,
                fontWeight: FontWeight.w600,
                letterSpacing: 0.5)),
      );

  Widget _tile({
    required IconData icon,
    required String title,
    String? subtitle,
    Widget? trailing,
    VoidCallback? onTap,
    bool danger = false,
  }) {
    final color = danger ? kRed : Colors.white;
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: cardDecoration(),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(18),
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 15),
            child: Row(
              children: [
                Icon(icon, color: danger ? kRed : kAccent, size: 22),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(title,
                          style: TextStyle(
                              color: color,
                              fontSize: 15,
                              fontWeight: FontWeight.w600)),
                      if (subtitle != null) ...[
                        const SizedBox(height: 2),
                        Text(subtitle,
                            style:
                                const TextStyle(color: kMuted, fontSize: 12)),
                      ],
                    ],
                  ),
                ),
                trailing ??
                    (onTap != null && !danger
                        ? const Icon(Icons.chevron_right, color: kMuted)
                        : const SizedBox.shrink()),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _switchTile({
    required IconData icon,
    required String title,
    required bool value,
    required bool enabled,
    required ValueChanged<bool> onChanged,
  }) {
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: cardDecoration(),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 7),
      child: Row(
        children: [
          Icon(icon, color: kAccent, size: 22),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title,
                    style: const TextStyle(
                        color: Colors.white,
                        fontSize: 15,
                        fontWeight: FontWeight.w600)),
                if (!enabled)
                  const Text('Indisponible sur cet appareil',
                      style: TextStyle(color: kMuted, fontSize: 11)),
              ],
            ),
          ),
          Switch(
            value: value,
            activeThumbColor: kAccent,
            onChanged: enabled ? onChanged : null,
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// RecoveryPhraseScreen — shown only after re-auth.
// ---------------------------------------------------------------------------

class RecoveryPhraseScreen extends StatelessWidget {
  const RecoveryPhraseScreen({super.key});
  @override
  Widget build(BuildContext context) {
    final mnemonic = WalletService.instance.mnemonic ?? '';
    final words = mnemonic.split(' ');
    return Scaffold(
      appBar: AppBar(title: const Text('Phrase de récupération')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(24, 8, 24, 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: kRed.withValues(alpha: 0.10),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: kRed.withValues(alpha: 0.3)),
                ),
                child: const Row(
                  children: [
                    Icon(Icons.visibility_off_outlined, color: kRed, size: 20),
                    SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        'Ne la montrez à personne et ne la saisissez sur aucun site.',
                        style: TextStyle(
                            color: Colors.white, fontSize: 12.5, height: 1.4),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 18),
              Expanded(
                child: SingleChildScrollView(
                  child: GridView.builder(
                    shrinkWrap: true,
                    physics: const NeverScrollableScrollPhysics(),
                    gridDelegate:
                        const SliverGridDelegateWithFixedCrossAxisCount(
                      crossAxisCount: 2,
                      childAspectRatio: 3.2,
                      crossAxisSpacing: 12,
                      mainAxisSpacing: 12,
                    ),
                    itemCount: words.length,
                    itemBuilder: (_, i) => Container(
                      padding: const EdgeInsets.symmetric(horizontal: 14),
                      alignment: Alignment.centerLeft,
                      decoration: cardDecoration(),
                      child: Row(
                        children: [
                          Text('${i + 1}',
                              style: const TextStyle(
                                  color: kMuted,
                                  fontSize: 12,
                                  fontWeight: FontWeight.w600)),
                          const SizedBox(width: 10),
                          Text(words[i],
                              style: const TextStyle(
                                  color: Colors.white,
                                  fontSize: 15,
                                  fontWeight: FontWeight.w600)),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 12),
              GhostButton(
                label: 'Copier la phrase',
                icon: Icons.copy,
                onPressed: () async {
                  await Clipboard.setData(ClipboardData(text: mnemonic));
                  if (!context.mounted) return;
                  showToast(context, 'Phrase copiée.');
                },
              ),
            ],
          ),
        ),
      ),
    );
  }
}

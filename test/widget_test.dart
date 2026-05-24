import 'package:flutter_test/flutter_test.dart';

import 'package:tchipa_wallet/main.dart';

void main() {
  test('formatAmount handles zero and trims trailing zeros', () {
    expect(WalletService.formatAmount(BigInt.zero, 6), '0');
    expect(
      WalletService.formatAmount(BigInt.from(1500000), 6),
      '1.5',
    );
    expect(
      WalletService.formatAmount(BigInt.from(1234567), 6),
      '1.234567',
    );
  });

  test('parseAmount round-trips through formatAmount', () {
    final raw = WalletService.parseAmount('12.345', 6);
    expect(raw, BigInt.from(12345000));
    expect(WalletService.formatAmount(raw, 6), '12.345');
  });

  test('parseAmount rejects garbage', () {
    expect(() => WalletService.parseAmount('abc', 6), throwsFormatException);
    expect(() => WalletService.parseAmount('', 6), throwsFormatException);
  });
}

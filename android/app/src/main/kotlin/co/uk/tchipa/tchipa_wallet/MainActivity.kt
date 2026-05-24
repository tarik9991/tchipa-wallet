package co.uk.tchipa.tchipa_wallet

import io.flutter.embedding.android.FlutterFragmentActivity

// FlutterFragmentActivity (not FlutterActivity) is required by the local_auth
// plugin so the biometric prompt can attach to a FragmentActivity.
class MainActivity : FlutterFragmentActivity()

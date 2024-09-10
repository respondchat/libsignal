cargo b -p react-native --target aarch64-apple-ios --release
cargo b -p react-native --target aarch64-apple-ios-sim --release
# cargo b -p react-native --target aarch64-apple-darwin --release
# cargo b -p react-native --target aarch64-linux-android  --release

install_name_tool -id @rpath/libsignal-ios.dylib ../../target/aarch64-apple-ios/release/libreact_native.dylib
install_name_tool -id @rpath/libsignal-ios-sim.dylib ../../target/aarch64-apple-ios-sim/release/libreact_native.dylib
strip -S -x ../../target/aarch64-apple-ios/release/libreact_native.dylib
strip -S -x ../../target/aarch64-apple-ios-sim/release/libreact_native.dylib

cp ../../target/aarch64-apple-ios/release/libreact_native.dylib ../../../../app/client/ios/libsignal-ios.dylib
cp ../../target/aarch64-apple-ios-sim/release/libreact_native.dylib ../../../../app/client/ios/libsignal-ios-sim.dylib

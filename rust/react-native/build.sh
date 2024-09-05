cargo b -p react-native --target aarch64-apple-ios --release
# cargo b -p react-native --target aarch64-apple-darwin --release
# cargo b -p react-native --target aarch64-apple-ios-sim --release
# cargo b -p react-native --target aarch64-linux-android  --release
install_name_tool -id @rpath/libreact_native.dylib ../../target/aarch64-apple-ios/release/libreact_native.dylib
cp ../../target/aarch64-apple-ios/release/libreact_native.dylib ../../../../app/client/ios/
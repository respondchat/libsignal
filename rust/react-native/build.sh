export IPHONEOS_DEPLOYMENT_TARGET=13.4

# cargo lipo --release -p react-native
cargo b --release -p react-native --target aarch64-apple-ios
cargo b --release -p react-native --target aarch64-apple-ios-sim
cargo b --release -p react-native --target x86_64-apple-ios
# cargo b --release -p react-native --target aarch64-apple-darwin
# cargo b --release -p react-native --target aarch64-linux-android 

install_name_tool -id @rpath/libsignal-ios.dylib ../../target/aarch64-apple-ios/release/libreact_native.dylib
install_name_tool -id @rpath/libsignal-ios-sim.dylib ../../target/aarch64-apple-ios-sim/release/libreact_native.dylib
install_name_tool -id @rpath/libsignal-ios-sim.dylib ../../target/x86_64-apple-ios/release/libreact_native.dylib
# strip -S -x ../../target/aarch64-apple-ios/release/libreact_native.dylib
# strip -S -x ../../target/aarch64-apple-ios-sim/release/libreact_native.dylib
# strip -S -x ../../target/x86_64-apple-ios/release/libreact_native.dylib

cp ../../target/aarch64-apple-ios/release/libreact_native.dylib ../../../../app/client/ios/libsignal-ios.dylib
cp ../../target/aarch64-apple-ios/release/libreact_native.a ../../../../app/client/ios/libsignal-ios.a
cp ../../target/aarch64-apple-ios-sim/release/libreact_native.dylib ../../../../app/client/ios/libsignal-ios-sim.dylib
cp ../../target/aarch64-apple-ios-sim/release/libreact_native.a ../../../../app/client/ios/libsignal-ios-sim.a
cp ../../target/x86_64-apple-ios/release/libreact_native.dylib ../../../../app/client/ios/libsignal-ios-sim-x86.dylib
cp ../../target/x86_64-apple-ios/release/libreact_native.a ../../../../app/client/ios/libsignal-ios-sim-x86.a
cd ../../../../app/client/ios/
lipo libsignal-ios-sim.dylib libsignal-ios-sim-x86.dylib -create -output libsignal-ios-sim.dylib
lipo libsignal-ios-sim.a libsignal-ios-sim-x86.a -create -output libsignal-ios-sim.a
rm libsignal-ios-sim-x86.dylib
rm libsignal-ios-sim-x86.a

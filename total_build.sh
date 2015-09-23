#/bin/sh
echo "\n<-------------------1. TOTAL BUILD START------------------->"
echo "clang++ -std=c++11 -arch armv7 /prog/amci/main.cpp /prog/amci/base64.cpp /prog/amci/md5.cpp /prog/amci/memorymap.cpp /prog/amci/module.cpp /prog/amci/util.cpp -o /prog/amci/obj/amci -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.9.sdk/"

# for iOS
#clang++ -std=c++11 -arch armv7 /prog/amci/main.cpp /prog/amci/base64.cpp /prog/amci/md5.cpp /prog/amci/module.cpp /prog/amci/memorymap.cpp /prog/amci/util.cpp -o /prog/amci/obj/ios/amci -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS7.1.sdk/
clang++ -std=c++11 -arch armv7 main.cpp packet.cpp base64.cpp md5.cpp module.cpp memorymap.cpp util.cpp -o ./ios/amci -I./lib/include -L./lib/lib -lpcap -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS8.4.sdk/


# for OSX
#clang++ -std=c++11 /prog/amci/main.cpp /prog/amci/base64.cpp /prog/amci/md5.cpp /prog/amci/module.cpp /prog/amci/memorymap.cpp /prog/amci/util.cpp -o /prog/amci/obj/osx/amci -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.8.sdk/

echo "\n<-------------------2. INJECTION ENTITLEMENTS TO AMCI------>"
echo "/var/root/temp/ldid/ldid -S/prog/ent.xml /prog/amci/obj/amci"
/var/root/shell/util/ldid/ldid -S./ent.xml ./ios/amci
#/var/root/temp/ldid/ldid -S/prog/amci/ent.xml /prog/amci/obj/osx/amci

echo "\n<-------------------3. MOVE AMCI TO IPHONE----------------->"
echo "/prog/amci/obj/amci -----> iPhone@:var/root/amci/amci\n"
sshpass -p 'alpine' scp -P 2222  ./ios/amci root@127.0.0.1:/var/root/amci/ 
#sshpass -p 'dbfpzk12' scp -P 2222  ./ios/amci root@127.0.0.1:/var/root/amci/ 
#sshpass -p 'fsa9119' scp -P 2222  /prog/amci/obj/ios/amci root@127.0.0.1:/var/root/amci/ 


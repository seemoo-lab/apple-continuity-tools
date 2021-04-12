#import <Foundation/Foundation.h>
#import <Security/Security.h>

int main(int argc, const char * argv[]) {
    sleep(1);
    NSDictionary *query = @{(id)kSecClass: (id)kSecClassGenericPassword,
                            (id)kSecAttrLabel: @"org.owlink.findme",
                            (id)kSecReturnData: (id)kCFBooleanTrue};
    
    CFTypeRef item;
    OSStatus res = SecItemCopyMatching((CFDictionaryRef)query, &item);
    if (res != 0) {
        NSLog(@"Failed to extract item: %@", SecCopyErrorMessageString(res, NULL));
    }
    return 0;
}

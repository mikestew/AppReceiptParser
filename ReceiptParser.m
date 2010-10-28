//
//  ReceiptParser.m
//  AppStoreReceipt
//
//  Created by Mike Stewart on 10/26/10.
//  Copyright 2010 Two Dogs Software, LLC. All rights reserved.
//

#import "ReceiptParser.h"

#include <openssl/pkcs7.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
// For GUID
#import <IOKit/IOKitLib.h>
#import <Foundation/Foundation.h>

@implementation ReceiptParser

NSString *kReceiptBundleIdentifer = @"BundleIdentifier";
NSString *kReceiptBundleIdentiferData = @"BundleIdentifierData";
NSString *kReceiptVersion = @"Version";
NSString *kReceiptOpaqueValue = @"OpaqueValue";
NSString *kReceiptHash = @"Hash";

// Based on sample code posted by Matthew Stevens
// https://devforums.apple.com/message/317799
// Add -lcrypto to "Other Linker Flags" in project build settings
- (NSDictionary *)dictionaryWithAppStoreReceipt:(NSString *)path {
    enum ATTRIBUTES {
        ATTR_START = 1,
        BUNDLE_ID,
        VERSION,
        OPAQUE_VALUE,
        HASH,
        ATTR_END
    };
    
    // Expected input is a PKCS7 container with signed data containing
    // an ASN.1 SET of SEQUENCE structures. Each SEQUENCE contains
    // two INTEGERS and an OCTET STRING.
    
    FILE *fp = fopen([path fileSystemRepresentation], "rb");
    if (fp == NULL)
        return nil;
    
    PKCS7 *p7 = d2i_PKCS7_fp(fp, NULL);
    fclose(fp);
    
    if (!PKCS7_type_is_signed(p7)) {
        PKCS7_free(p7);
        return nil;
    }
    
    if (!PKCS7_type_is_data(p7->d.sign->contents)) {
        PKCS7_free(p7);
        return nil;
    }
    
    ASN1_OCTET_STRING *octets = p7->d.sign->contents->d.data;   
    const unsigned char *p = octets->data;
    const unsigned char *end = p + octets->length;
    
    int type = 0;
    int xclass = 0;
    long length = 0;
    
    ASN1_get_object(&p, &length, &type, &xclass, end - p);
    if (type != V_ASN1_SET) {
        PKCS7_free(p7);
        return nil;
    }
    
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    
    while (p < end) {
        ASN1_get_object(&p, &length, &type, &xclass, end - p);
        if (type != V_ASN1_SEQUENCE)
            break;
        
        const unsigned char *seq_end = p + length;
        
        int attr_type = 0;
        int attr_version = 0;
        
        // Attribute type
        ASN1_get_object(&p, &length, &type, &xclass, seq_end - p);
        if (type == V_ASN1_INTEGER && length == 1) {
            attr_type = p[0];
        }
        p += length;
        
        // Attribute version
        ASN1_get_object(&p, &length, &type, &xclass, seq_end - p);
        if (type == V_ASN1_INTEGER && length == 1) {
            attr_version = p[0];
        }
        p += length;
        
        // Only parse attributes we're interested in
        if (attr_type > ATTR_START && attr_type < ATTR_END) {
            NSString *key;
            
            ASN1_get_object(&p, &length, &type, &xclass, seq_end - p);
            if (type == V_ASN1_OCTET_STRING) {
                
                // Bytes
                if (attr_type == BUNDLE_ID || attr_type == OPAQUE_VALUE || attr_type == HASH) {
                    NSData *data = [NSData dataWithBytes:p length:length];
                    
                    switch (attr_type) {
                        case BUNDLE_ID:
                            // This is included for hash generation
                            key = kReceiptBundleIdentiferData;
                            break;
                        case OPAQUE_VALUE:
                            key = kReceiptOpaqueValue;
                            break;
                        case HASH:
                            key = kReceiptHash;
                            break;
                    }
                    
                    [info setObject:data forKey:key];
                }
                
                // Strings
                if (attr_type == BUNDLE_ID || attr_type == VERSION) {
                    int str_type = 0;
                    long str_length = 0;
                    const unsigned char *str_p = p;
                    ASN1_get_object(&str_p, &str_length, &str_type, &xclass, seq_end - str_p);
                    if (str_type == V_ASN1_UTF8STRING) {
                        NSString *string = [[[NSString alloc] initWithBytes:str_p
                                                                     length:str_length
                                                                   encoding:NSUTF8StringEncoding] autorelease];
                    
                        switch (attr_type) {
                            case BUNDLE_ID:
                                key = kReceiptBundleIdentifer;
                                break;
                            case VERSION:
                                key = kReceiptVersion;
                                break;
                        }
                        
                        [info setObject:string forKey:key];
                    }
                }
            }
            p += length;
        }
        
        // Skip any remaining fields in this SEQUENCE
        while (p < seq_end) {
            ASN1_get_object(&p, &length, &type, &xclass, seq_end - p);
            p += length;
        }
    }
    
    PKCS7_free(p7);
    
    return info;
}

- (BOOL) receiptIsValid: (NSString *)path {
	// From Apple's web page
	// https://developer.apple.com/devcenter/mac/documents/validating.html#//apple_ref/doc/uid/DontLinkBookID_1-CH1-SW6
	// Validate a Receipt
	// 
	// Perform the following tests, in this order:
	// 
	// If there is no receipt, verification fails.
	// 
	// If the receipt is not properly signed by Apple, verification fails.
	// 
	// If the bundle identifier in the receipt does not match the value for CFBundleIdentifier in the Info.plist file,
	// verification fails.
	// 
	// If the version identifier string in the receipt does not match the value for CFBundleShortVersionString in 
	// the Info.plist file, verification fails.
	// 
	// Concatenate the bytes of the computer’s GUID, the opaque value (the attribute of type 4), and the 
	// bundle identifier from the receipt. 
	// Compute the SHA-1 hash. If the result does not match the hash in the receipt, verification fails.
	// If all of the above checks pass, verification passes.
	//
	// ***************************
	// *Note* that this sample method only does the first two, and the last (compare the hashes). Real-world needs to also check
	// the bundle identifier and the version against the actual identifier and version.
	NSDictionary *receipt = [self dictionaryWithAppStoreReceipt:path];
		 
	// Example GUID for use with example receipt
	// See the copy_mac_address method (below) from Apple's site as a
	// real-world example of how to obtain the GUID from a real computer.
	unsigned char guid[] = { 0x00, 0x17, 0xf2, 0xc4, 0xbc, 0xc0 };

	NSMutableData *input = [NSMutableData data];
	[input appendBytes:guid length:sizeof(guid)];
	[input appendData:[receipt objectForKey:kReceiptOpaqueValue]];
	[input appendData:[receipt objectForKey:kReceiptBundleIdentiferData]];

	NSMutableData *hash = [NSMutableData dataWithLength:SHA_DIGEST_LENGTH];
	SHA1([input bytes], [input length], [hash mutableBytes]);
	
	// TODO: Is the bundle idenifier the same as the executing application?
	// When using the sample receipt, it would fail unless the identifier were modified to "com.example.SampleApp"
	// TODO: Is the version string the same as the executing application?
	// Same thing here, unless the version is coincidentally "1.0.2"
	if ([hash isEqualToData:[receipt objectForKey:kReceiptHash]]) {
		return YES;
	}
	else {
		return NO;
	}
}

// Returns a CFData object, containing the machine's GUID.
// Requires IOKit framework
CFDataRef copy_mac_address(void)
{
    kern_return_t             kernResult;
    mach_port_t               master_port;
    CFMutableDictionaryRef    matchingDict;
    io_iterator_t             iterator;
    io_object_t               service;
    CFDataRef                 macAddress = nil;
 
    kernResult = IOMasterPort(MACH_PORT_NULL, &master_port);
    if (kernResult != KERN_SUCCESS) {
        printf("IOMasterPort returned %d\n", kernResult);
        return nil;
    }
 
    matchingDict = IOBSDNameMatching(master_port, 0, "en0");
    if(!matchingDict) {
        printf("IOBSDNameMatching returned empty dictionary\n");
        return nil;
    }
 
    kernResult = IOServiceGetMatchingServices(master_port, matchingDict, &iterator);
    if (kernResult != KERN_SUCCESS) {
        printf("IOServiceGetMatchingServices returned %d\n", kernResult);
        return nil;
    }
 
    while((service = IOIteratorNext(iterator)) != 0)
    {
        io_object_t        parentService;
 
        kernResult = IORegistryEntryGetParentEntry(service, kIOServicePlane, &parentService);
        if(kernResult == KERN_SUCCESS)
        {
            if(macAddress) CFRelease(macAddress);
 
            macAddress = IORegistryEntryCreateCFProperty(parentService, CFSTR("IOMACAddress"), kCFAllocatorDefault, 0);
            IOObjectRelease(parentService);
        }
        else {
            printf("IORegistryEntryGetParentEntry returned %d\n", kernResult);
        }
 
        IOObjectRelease(service);
    }
 
    return macAddress;
}

// An example usage of the function.
// int main (int argc, const char * argv[]) {
//     NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
// 
//     NSLog(@"copy_mac_address:%@", copy_mac_address());
// 
//     [pool drain];
//     return 0;
// }

@end

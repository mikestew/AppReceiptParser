//
//  ReceiptParser.h
//  AppStoreReceipt
//
//  Created by Mike Stewart on 10/26/10.
//  Sample code based on Apple dev forum post from Matthew Stevens
//  Computer GUID method from Apple, Inc.
//  Copyright 2010 Two Dogs Software, LLC. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface ReceiptParser : NSObject {


}

- (NSDictionary *)dictionaryWithAppStoreReceipt:(NSString *)path; 
- (BOOL) receiptIsValid: (NSString *)path;

//CFDataRef copy_mac_address(void);
@end

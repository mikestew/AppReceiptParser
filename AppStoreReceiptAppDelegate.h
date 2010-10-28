//
//  AppStoreReceiptAppDelegate.h
//  AppStoreReceipt
//
//  Created by Mike Stewart on 10/26/10.
//  Copyright 2010 Two Dogs Software, LLC. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface AppStoreReceiptAppDelegate : NSObject <NSApplicationDelegate> {
    NSWindow *window;
	IBOutlet NSTextField *validationResult;
	IBOutlet NSTextField *bundleIdentifier;
	IBOutlet NSTextField *appVersion;
}

@property (assign) IBOutlet NSWindow *window;
- (IBAction) validateReciept: (id) sender;
@end

//
//  AppStoreReceiptAppDelegate.m
//  AppStoreReceipt
//
//  Created by Mike Stewart on 10/26/10.
//  Copyright 2010 Two Dogs Software, LLC. All rights reserved.
//

#import "AppStoreReceiptAppDelegate.h"
#import "ReceiptParser.h"

@implementation AppStoreReceiptAppDelegate

@synthesize window;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
	// Insert code here to initialize your application 
}

- (IBAction) validateReciept: (id) sender {
	NSBundle *appBundle = [NSBundle mainBundle];
	NSString *pathToReceipt = [appBundle pathForResource:@"receipt" ofType:nil];
	ReceiptParser *parser = [[ReceiptParser alloc] init];
	NSDictionary *receipt = [parser dictionaryWithAppStoreReceipt: pathToReceipt];
	if ([parser receiptIsValid:pathToReceipt]) {
		[validationResult setStringValue:@"Receipt is valid. Execution can continue."];
	}
	else {
		[validationResult setStringValue:@"Receipt is invalid. Halt further execution."];
	}
	[bundleIdentifier setStringValue:[receipt valueForKey:@"BundleIdentifier"]];
	[appVersion setStringValue:[receipt valueForKey:@"Version"]];
}

@end

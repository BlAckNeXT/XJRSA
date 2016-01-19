//
//  XJRSA.h
//  XJRSA
//
//  Created by 张雪剑 on 16/1/19.
//  Copyright © 2016年 Sysw1n. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface XJRSA : NSObject

/*!
 * The public key file name
 */
@property (nonatomic, copy) NSString *publicKey;

/*!
 * The private key file name
 */
@property (nonatomic, copy) NSString *privateKey;



- (NSString *)publicEncrypt:(NSString *)plainText;
- (NSString *)privateDecrypt:(NSString *)cipherText;
- (NSString *)privateEncrypt:(NSString *)plainText;
- (NSString *)publicDecrypt:(NSString *)cipherText;
- (BOOL)generateRSAKeyPairWithKeySize:(int)keySize;
#pragma mark 返回公钥路径
- (NSString *)returnPublicKeyPath:(NSString *)publicKey;

#pragma mark 返回私钥路径
- (NSString *)returnPrivateKeyPath:(NSString *)privateKey;

+ (XJRSA *)sharedInstance;

@end

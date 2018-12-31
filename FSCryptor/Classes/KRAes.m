//
//  KRAES.m
//  KRAES
//
//  Created by Kalvar on 2014/6/19.
//  Copyright (c) 2014年 Kalvar. All rights reserved.
//

#import "KRAes.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation KRAes (fixAes256)

+ (NSData *)aes256WithData:(NSData *)data key:(NSString *)pwd isEncrypt:(BOOL)isEncrypt{
    //+1 is the check code.
    char keyPattern[kCCKeySizeAES256 + 1];
    bzero(keyPattern, sizeof(keyPattern));
    [pwd getCString:keyPattern maxLength:sizeof(keyPattern) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    size_t bufferSize     = dataLength + kCCBlockSizeAES128;
    void *buffers         = malloc(bufferSize);
    
    size_t totalBytes = 0;
    CCCryptorStatus cryptStatus = CCCrypt(
                           isEncrypt?kCCEncrypt:kCCDecrypt,
                           kCCAlgorithmAES128, // fdd.AES 是一个迭代的、对称密钥分组的密码，它可以使用128、192 和 256 位密钥，并且用 128 位（16字节）分组加密和解密数据
                           kCCOptionPKCS7Padding | kCCOptionECBMode,// 如果我们第三个变量写成kCCOptionPKCS7Padding|kCCOptionECBMode，就表示运用了ECB加密模式，并且使用PKCS7Padding的填充模式进行加密。所以单单使用kCCOptionPKCS7Padding就代表了CBC加密模式。
                           keyPattern,
                           kCCKeySizeAES256,
                           NULL,
                           [data bytes],
                           dataLength,
                           buffers,
                           bufferSize,
                           &totalBytes);
    
    if (cryptStatus == kCCSuccess){
        return [NSMutableData dataWithBytesNoCopy:buffers length:totalBytes];
    }
    free(buffers);
    return nil;
}

@end

@implementation KRAes

/*
 * @ 加密
 *   - _key : your private key password with 32 Bytes
 */
+ (NSData *)encryptAES256WithData:(NSData *)data password:(NSString *)key{
    return [self aes256WithData:data key:key isEncrypt:YES];
}

/*
 * @ 解密
 *   - _key : your private key password with 32 Bytes
 */
+ (NSData *)decryptAES256WithData:(NSData *)data password:(NSString *)key{
    return [self aes256WithData:data key:key isEncrypt:NO];
}

@end





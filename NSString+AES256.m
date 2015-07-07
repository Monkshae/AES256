//
//  NSString+AES256.m
//  Gengmei
//
//  Created by Sean Lee on 6/12/15.
//  Copyright (c) 2015 Wanmeichuangyi. All rights reserved.
//

#import "NSString+AES256.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import "GTMBase64.h"

@implementation NSString (AES256)

+ (NSString *)AES256Encrypt:(NSString *)string  WithKey:(NSString *)keyString
{
    
    //密钥
    NSData *key = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    //明文数据
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    // Init cryptor
    CCCryptorRef cryptor = NULL;
    //IV:初始化16字节的随机向量
    char iv[16];
    for (int i = 0; i<16; i++) {
        iv[i] = arc4random()%255;//一个字节长的随机数
    }
    //Create Cryptor
    CCCryptorStatus  create = CCCryptorCreateWithMode(kCCEncrypt,
                                                      kCCModeCBC,           //CBC模式
                                                      kCCAlgorithmAES128,   //分组密码块长度
                                                      ccNoPadding,          //无填充模式
                                                      iv,                   // can be NULL, because null is full of zeros
                                                      key.bytes,            //密钥
                                                      key.length,           //密钥长度
                                                      NULL,
                                                      0,
                                                      0,
                                                      0,                    //这里参数只在CTR下有用，本初填0即可
                                                      &cryptor);
    
    if (create == kCCSuccess)
    {
        //alloc number of bytes written to data Out
        size_t numBytesCrypted;
        //自定义填充明文算法
        NSUInteger dataLength = [data length];
        int diff = 128 - (dataLength % 128);
        unsigned long newSize = 0;
        if(diff > 0)
            newSize = dataLength + diff;
        
        char dataPtr[newSize];
        memcpy(dataPtr, [data bytes], [data length]);
        for(int i = 0; i < diff; i++){
            char character = diff;
            dataPtr[i + dataLength] = character;
        }
//        printf("%lu",sizeof(dataPtr));
        
        /*初始化加密后的data，并开辟好空间长度,查阅相关文档：对于分组密码，加密后的数据长度总是小于或者等于  加密前数据长度+单个分组密码块长度之和*/
        NSMutableData *cipherData= [NSMutableData dataWithLength: sizeof(dataPtr)+kCCBlockSizeAES128];
        
        /*Update Cryptor,得到加密后data以及我们需要的数据长度,这里可以看到cipherData的长度是小于或者等于outLength的
         */
        CCCryptorStatus  update = CCCryptorUpdate(cryptor,
                                                  dataPtr,
                                                  sizeof(dataPtr),
                                                  cipherData.mutableBytes,
                                                  cipherData.length,
                                                  &numBytesCrypted);
        
        if (update == kCCSuccess)
        {
            //通过outLength截图我们需要的数据长度
            cipherData.length = numBytesCrypted;
            //Final Cryptor,最终生成最终的密文，装载给cipherData
            CCCryptorStatus final = CCCryptorFinal(cryptor,                 //CCCryptorRef cryptorRef,
                                                   cipherData.mutableBytes, //void   *dataOut,
                                                   cipherData.length,       //size_t dataOutAvailable,
                                                   &numBytesCrypted);             //size_t *dataOutMoved)
            
            if (final == kCCSuccess){
                //Release Cryptor
                CCCryptorRelease(cryptor);
            }
            
            //最终结果= 初始向量+密文,这样服务器才可以拿到初始向量，用密钥解码
            NSMutableData *resultData= [NSMutableData dataWithLength:0];
            [resultData appendBytes:iv length:sizeof(iv)];
            [resultData appendBytes:cipherData.bytes length:cipherData.length];
            //最终结果再base64转码
            NSString * resultStr = [GTMBase64 stringByEncodingData:resultData];
//            NSLog(@"%@",resultStr);
            return resultStr;
        }
    }
    else{
        NSLog(@"加密失败");
    }
    return nil;
    
}

+ (NSString *)AES256DecryptString:(NSString *) string WithKey:(NSString *)keyString
{
    //Key to Data
    NSData *key = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    // Init cryptor
    CCCryptorRef cryptor = NULL;
    //IV:获取密文里的随机向量
    
    NSData *data = [GTMBase64 decodeString:string];
    
    NSMutableData * iv = [NSMutableData dataWithBytes:data.bytes length:kCCKeySizeAES256];
    
    
//    char iv[16];
//    for (int i = 0; i<16; i++) {
//        iv[i] = 0;
//    }
    // Create Cryptor
    CCCryptorStatus createDecrypt = CCCryptorCreateWithMode(kCCDecrypt, // operation
                                                            kCCModeCBC, // mode CTR
                                                            kCCAlgorithmAES, // Algorithm
                                                            ccNoPadding, // padding
                                                            iv.bytes, // can be NULL, because null is full of zeros
                                                            key.bytes, // key
                                                            key.length, // keylength
                                                            NULL, //const void *tweak
                                                            0, //size_t tweakLength,
                                                            0, //int numRounds,
                                                            0, //CCModeOptions options,
                                                            &cryptor); //CCCryptorRef *cryptorRef
    
    
    if (createDecrypt == kCCSuccess)
    {
        // Alloc Data Out
        
        NSMutableData * realData = [NSMutableData dataWithBytes:data.bytes + 16 length:data.length - 16];
        
        NSMutableData *cipherDataDecrypt = [NSMutableData dataWithLength:realData.length + kCCBlockSizeAES128];
        
        //alloc number of bytes written to data Out
        size_t outLengthDecrypt;
        
        //Update Cryptor
        CCCryptorStatus updateDecrypt = CCCryptorUpdate(cryptor,
                                                        realData.bytes, //const void *dataIn,
                                                        realData.length,  //size_t dataInLength,
                                                        cipherDataDecrypt.mutableBytes, //void *dataOut,
                                                        cipherDataDecrypt.length, // size_t dataOutAvailable,
                                                        &outLengthDecrypt); // size_t *dataOutMoved)
        
        if (updateDecrypt == kCCSuccess)
        {
            //Cut Data Out with nedded length
            cipherDataDecrypt.length = outLengthDecrypt;
            
            //Final Cryptor
            CCCryptorStatus final = CCCryptorFinal(cryptor, //CCCryptorRef cryptorRef,
                                                   cipherDataDecrypt.mutableBytes, //void *dataOut,
                                                   cipherDataDecrypt.length, // size_t dataOutAvailable,
                                                   &outLengthDecrypt); // size_t *dataOutMoved)
            
            if (final == kCCSuccess)
            {
                //Release Cryptor
                //CCCryptorStatus release =
                CCCryptorRelease(cryptor); //CCCryptorRef cryptorRef
            }
            // Data to String
            NSMutableString* cipherFinalDecrypt = [[NSMutableString alloc] initWithData:cipherDataDecrypt encoding:NSUTF8StringEncoding];
            
            int diff = [cipherFinalDecrypt characterAtIndex:cipherDataDecrypt.length - 1]; //  128字节的明文（填充字符）中填充字符的个数
            
            [cipherFinalDecrypt deleteCharactersInRange:NSMakeRange(cipherFinalDecrypt.length - diff, diff)];
            
//            printf("%d",diff);
            
            return cipherFinalDecrypt;
        }
    }
    else{
        //error
        NSLog(@"解密密失败");
    }
    
    return nil;

}





- (NSString *) stringFromMD5
{
    
    if(self == nil || [self length] == 0)
        return nil;
    
    const char *value = [self UTF8String];
    
    unsigned char outputBuffer[CC_MD5_DIGEST_LENGTH];
    CC_MD5(value, (uint32_t)strlen(value), outputBuffer);
    
    NSMutableString *outputString = [[NSMutableString alloc] initWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(NSInteger count = 0; count < CC_MD5_DIGEST_LENGTH; count++){
        [outputString appendFormat:@"%02x",outputBuffer[count]];
    }
    
    return outputString;
}


+(BOOL)validKey:(NSString*)key
{
    if( key==nil || key.length != kCCKeySizeAES256){
        return NO;
    }
    return YES;
}


@end

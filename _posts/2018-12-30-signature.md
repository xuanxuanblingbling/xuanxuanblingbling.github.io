---
title: Android P v3签名新特性
date: 2018-12-30 00:00:00
categories:
- CTF/Android
tags: signature
---

新版v3签名在v2的基础上，仍然采用检查整个压缩包的校验方式。不同的是在签名部分增可以添加新的证书，即可以不用修改ApplicationID来完成证书的更新迭代。

## 概述
![image](https://xuanxuanblingbling.github.io/assets/pic/sign1.png)

签名机制主要有两种用途：

- 使用特殊的key签名可以获取到一些不同的权限
- 验证数据保证不被篡改，防止应用被恶意的第三方覆盖

这里我们主要讨论第二个用途，即验证数据是否是可信的。应用程序的作者使用自己的私钥签名APK文件，并将签名与公钥一起发布到APK中，这个过程称之为签名。当应用程序被安装时，用发布的公钥去解析签名，并与文件的hash进行比对，这个过程叫验签。

显然这里我们尝试修改被签名数据的任何一部分都会导致验签失败，但是我们并不能防止重新签名。于是就存在一个问题：如何相信一个应用是正版应用？AOSP原生中并没有这种校验机制，如果是第一次安装，则默认相信自签名的应用。

但是当我们更新应用时，android根据应用的ApplicationID(一般与包名相同)来判断是否是同一个应用，并且要验证原来的应用与更新应用的证书是否匹配。但是在v1v2的签名版本中一个应用只允许用一个证书来校验，这时如果软件开发者想要更新证书并且完成软件的更新，是没有办法的，只能换用新的ApplicationID重新安装。

所以在v3新版本签名中加入了证书的旋转校验，即可以在一次的升级安装中使用新的证书，新的私钥来签名APK。当然这个新的证书是需要老证书来保证的，类似一个证书链。


## 签名块结构

在v1版本的签名中，签名以文件的形式存在于apk包中，这个版本的apk包就是一个标准的zip包。但是在v2版本的签名中，签名信息被塞到了apk文件本身中，这时apk已经不符合一个标准的zip压缩包的文件结构。v3版本签名中延续了v2的签名方式，仍然是将签名信息放到压缩包本身的结构中。但是在v3中添加了一种更新证书的方式，这部分更新证书的数据同样被放在了签名信息中。所以为了理解签名数据的具体结构，我们先了解正常ZIP结构

### ZIP

这里我用010editor打开自己压得一个内容flag.txt的压缩包，简单的说一下ZIP文件格式由一下三部分组成：

- 文件数据区（灰，白）
- 中央目录结构（粉）
- 中央目录结束标志（黄）

![image](https://xuanxuanblingbling.github.io/assets/pic/sign2.png)


真正的数据内容就是那段白色的数据，zip解析时，通过结束标志中找到中央目录的偏移，然后找到中心目录，然后从中心目录的每一条数据里找到文件数据的偏移，最后读取文件数据。可以简单的理解这种数据解析方式为：倒着往上找。

参考：[https://blog.csdn.net/a200710716/article/details/51644421](https://blog.csdn.net/a200710716/article/details/51644421)

### APK

使用v1签名的APK就是标准的ZIP结构，但使用v2v3签名的APK，文件本身已经不符合ZIP结构了，具体的变化就是：在文件数据区与中央目录结构之间插入了签名数据块，关于签名的各种数据，以及v3签名新添加的更新证书的数据，都保存在这个数据块中。

![image](https://xuanxuanblingbling.github.io/assets/pic/sign3.png)

可看到010editor的ZIP解析模板已经无法识别通过v2v3版本签名工具生成的APK文件。

### 结构分析

![image](https://xuanxuanblingbling.github.io/assets/pic/sign1.png)



v2版本签名块（APK Signing Block）本身又主要分成三部分:

- SignerData（签名者数据）：主要包括签名者的证书，整个APK完整性校验hash，以及一些必要信息
- Signature（签名）：开发者对SignerData部分数据的签名数据
- PublicKey（公钥）：用于验签的公钥数据

v3版本签名块也分成同样的三部分，与v2不同的是在SignerData部分，v3新增了attr块，其中是由更小的level块组成。每个level块中可以存储一个证书信息。前一个level块证书验证下一个level证书，以此类推。最后一个level块的证书，要符合SignerData中本身的证书，即用来签名整个APK的公钥所属于的证书。两个版本的签名块结构如下：

![image](https://xuanxuanblingbling.github.io/assets/pic/sign4.png)


## 验证签名

所谓验证签名，就是检查APK中的签名结构是否符合一定的要求，这里的签名实际上是APK的整体签名。而在签名块中，存在很多项数据需要验证，比如APK的摘要信息，证书信息，SDK版本信息等，这些都是APK的签名数据。所以在整个签名的验证中，以上信息是全部都要验证的。不过在v3版本中添加的新特性是针对验证证书信息的修订，所以接下来也是重点分析验签中的证书验证的部分。

### 验证签名流程

因为签名的验证就是发生在一个apk包的安装过程中，所以为了更清楚验证签名的时机，有必要了解整个安装的分类与大致流程。Android安装应用主要有如下四种方式：

- 系统应用安装：开机时完成，没有安装界面
- 网络下载的应用安装：通过市场应用完成，没有安装界面
- ADB工具安装：没有安装界面
- 第三方应用安装：通过packageinstall.apk应用安装，有安装界面

但是其实无论通过哪种方式安装都要通过PackageManagerService来完成安装的主要工作，最终在PMS中会去验证签名信息，流程如下

![image](https://xuanxuanblingbling.github.io/assets/pic/sign5.png)

安装过程中如果发现有v3签名块，则必须使用v3签名的验证机制，不能绕过。否则才使用v2签名的验证机制，以此类推。

### 验证完整性

数据完整性校验v3与v2版本相同，原理如下：

![image](https://xuanxuanblingbling.github.io/assets/pic/sign6.png)

签名块包括对apk第一部分，第二部分，第三部分的二进制内容做加密保护，摘要算法以及签名算法。签名块本身不做加密，这里需要特殊注意的是由于第三部分包含了对第二部分的引用偏移，因此如果签名块做了改变，比如在签名过程中增加一种签名算法，或者增加签名者等信息就会导致这个引用偏移发生改变，因此在算摘要的时候需要剔除这个因素要以第三部分对签名块的偏移来做计算。

### 验证证书

#### v2

v2版本签名验证证书步骤：

- 利用PublicKey解密Signature，得到SignerData的hash明文
- 计算SignerData的hash值
- 两个值进行比较，如果相同则认为APK没有被修改过，解析出SignerData中的证书。否则安装失败
- 如果是第一次安装，直接将证书保存在应用信息中
- 如果是更新安装，即设备中原来存在这个应用，验证之前的证书是否与本次解析的证书相同。若相同，则安装成功，否则失败

![image](https://xuanxuanblingbling.github.io/assets/pic/sign7.png)

#### v3

v3版本签名验证证书步骤：（前三步同v2）

- 利用PublicKey解密Signature，得到SignerData的hash明文
- 计算SignerData的hash值
- 两个值进行比较，如果相同则认为APK没有被修改过，解析出SignerData中的证书。否则安装失败
- 逐个解析出level块证书并验证，并保存为这个应用的历史证书
- 如果是第一次安装，直接将证书与历史证书一并保存在应用信息中
- 如果是更新安装，验证之前的证书与历史证书，是否与本次解析的证书或者历史证书中存在相同的证书，其中任意一个证书符合即可安装

![image](https://xuanxuanblingbling.github.io/assets/pic/sign8.png)

#### 新特性场景举例

其实就是当开发者需要更换证书时，即可直接用新证书新的私钥进行签名。不过为了让老应用相信新的证书，则需要用老证书来保证。举个例子，有两个level块：level 1与level 2：

- level 1放置老证书的信息
- level 2中放置新证书的信息以及这段数据的签名
- level 2中的签名是由老私钥进行签名的，则需要用老证书的公钥来验证
- 校验原来的证书与level 1 相同，则相信本次更新的level 2 的证书，即签名APK的证书
- 完成安装并记录新证书信息



## 关于v3签名的google注释

以下主要是在ApkSignatureSchemeV3Verifier.java文件中的有关于v3签名的一些函数的注释，官方原文可供参考

```
    /**
     * Returns the certificates associated with each signer for the given APK without verification.
     * This method is dangerous and should not be used, unless the caller is absolutely certain the
     * APK is trusted.  Specifically, verification is only done for the APK Signature Scheme v3
     * Block while gathering signer information.  The APK contents are not verified.
     *
     * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v3.
     * @throws IOException if an I/O error occurs while reading the APK file.
     */

     /**
     * Verifies APK Signature Scheme v3 signatures of the provided APK and returns the certificates
     * associated with each signer.
     *
     * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v3.
     * @throws SecurityException if an APK Signature Scheme v3 signature of this APK does not
     *         verify.
     * @throws IOException if an I/O error occurs while reading the APK file.
     */

     /**
     * Returns the APK Signature Scheme v3 block contained in the provided APK file and the
     * additional information relevant for verifying the block against the file.
     *
     * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v3.
     * @throws IOException if an I/O error occurs while reading the APK file.
     */

     /**
     * Verifies the contents of the provided APK file against the provided APK Signature Scheme v3
     * Block.
     *
     * @param signatureInfo APK Signature Scheme v3 Block and information relevant for verifying it
     *        against the APK file.
     */

     // make sure that the last certificate in the Proof-of-rotation record matches
     // the one used to sign this APK.


     // Proof-of-rotation struct:
     // A uint32 version code followed by basically a singly linked list of nodes, called levels
     // here, each of which have the following structure:
     // * length-prefix for the entire level
     //     - length-prefixed signed data (if previous level exists)
     //         * length-prefixed X509 Certificate
     //         * uint32 signature algorithm ID describing how this signed data was signed
     //     - uint32 flags describing how to treat the cert contained in this level
     //     - uint32 signature algorithm ID to use to verify the signature of the next level. The
     //         algorithm here must match the one in the signed data section of the next level.
     //     - length-prefixed signature over the signed data in this level.  The signature here
     //         is verified using the certificate from the previous level.
     // The linking is provided by the certificate of each level signing the one of the next.
```

## v3验签代码分析

![image](https://xuanxuanblingbling.github.io/assets/pic/sign9.png)

### PackageManagerService.InstallPackageLI()

无论是哪种方式的安装应用，最后都会执行到这个真正安装函数，这个函数位于PMS，这个函数代码比较长，这里保留比较关键的代码来说明

> frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java

```java
private void installPackageLI(InstallArgs args, PackageInstalledInfo res) {
		PackageParser pp = new PackageParser();
        pp.setSeparateProcesses(mSeparateProcesses);
        pp.setDisplayMetrics(mMetrics);
        pp.setCallback(mPackageParserCallback);

        Trace.traceBegin(TRACE_TAG_PACKAGE_MANAGER, "parsePackage");
        final PackageParser.Package pkg;
        try {
            pkg = pp.parsePackage(tmpPackageFile, parseFlags);
            DexMetadataHelper.validatePackageDexMetadata(pkg);
        } catch (PackageParserException e) {
            res.setError("Failed parse during installPackageLI", e);
            return;
        } finally {
            Trace.traceEnd(TRACE_TAG_PACKAGE_MANAGER);
        }
        try {
            // either use what we've been given or parse directly from the APK
            if (args.signingDetails != PackageParser.SigningDetails.UNKNOWN) {
                pkg.setSigningDetails(args.signingDetails);
            } else {
                PackageParser.collectCertificates(pkg, false /* skipVerify */);
            }
        } catch (PackageParserException e) {
            res.setError("Failed collect during installPackageLI", e);
            return;
        }
}
```
- 首先实例化一个PackageParser的对象pp，利用这个对象的parsePackage()方法，返回一个位于PackageParser类中的内部类Package的实例对象pkg，其中包含着要安装的应用的一些信息
- 利用PackageParser的一个静态方法collectCertificates(pkg,false)收集证书，这里就是验签的入口了

### PackageParser.collectCertificates()

> frameworks/base/core/java/android/content/pm/PackageParser.java

```java
	public static void collectCertificates(Package pkg, boolean skipVerify)
            throws PackageParserException {
        collectCertificatesInternal(pkg, skipVerify);
        final int childCount = (pkg.childPackages != null) ? pkg.childPackages.size() : 0;
        for (int i = 0; i < childCount; i++) {
            Package childPkg = pkg.childPackages.get(i);
            childPkg.mSigningDetails = pkg.mSigningDetails;
        }
    }

    private static void collectCertificatesInternal(Package pkg, boolean skipVerify)
            throws PackageParserException {
        pkg.mSigningDetails = SigningDetails.UNKNOWN;

        Trace.traceBegin(TRACE_TAG_PACKAGE_MANAGER, "collectCertificates");
        try {
            collectCertificates(pkg, new File(pkg.baseCodePath), skipVerify);

            if (!ArrayUtils.isEmpty(pkg.splitCodePaths)) {
                for (int i = 0; i < pkg.splitCodePaths.length; i++) {
                    collectCertificates(pkg, new File(pkg.splitCodePaths[i]), skipVerify);
                }
            }
        } finally {
            Trace.traceEnd(TRACE_TAG_PACKAGE_MANAGER);
        }
    }

    private static void collectCertificates(Package pkg, File apkFile, boolean skipVerify)
            throws PackageParserException {
        final String apkPath = apkFile.getAbsolutePath();

        int minSignatureScheme = SigningDetails.SignatureSchemeVersion.JAR;
        if (pkg.applicationInfo.isStaticSharedLibrary()) {
            // must use v2 signing scheme
            minSignatureScheme = SigningDetails.SignatureSchemeVersion.SIGNING_BLOCK_V2;
        }
        SigningDetails verified;
        if (skipVerify) {
            // systemDir APKs are already trusted, save time by not verifying
            verified = ApkSignatureVerifier.plsCertsNoVerifyOnlyCerts(
                        apkPath, minSignatureScheme);
        } else {
            verified = ApkSignatureVerifier.verify(apkPath, minSignatureScheme);
        }

        // Verify that entries are signed consistently with the first pkg
        // we encountered. Note that for splits, certificates may have
        // already been populated during an earlier parse of a base APK.
        if (pkg.mSigningDetails == SigningDetails.UNKNOWN) {
            pkg.mSigningDetails = verified;
        } else {
            if (!Signature.areExactMatch(pkg.mSigningDetails.signatures, verified.signatures)) {
                throw new PackageParserException(
                        INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES,
                        apkPath + " has mismatched certificates");
            }
        }
    }
```

- collectCertificates重载到三个参数的方法，因为跳过检查的参数为false，最终调用ApkSignatureVerifier类中的verify方法

### ApkSignatureVerifier.verify()

> frameworks/base/core/java/android/util/apk/ApkSignatureVerifier.java

```java
public static PackageParser.SigningDetails verify(String apkPath,
            @SignatureSchemeVersion int minSignatureSchemeVersion)
            throws PackageParserException {

        if (minSignatureSchemeVersion > SignatureSchemeVersion.SIGNING_BLOCK_V3) {
            // V3 and before are older than the requested minimum signing version
            throw new PackageParserException(INSTALL_PARSE_FAILED_NO_CERTIFICATES,
                    "No signature found in package of version " + minSignatureSchemeVersion
            + " or newer for package " + apkPath);
        }

        // first try v3
        Trace.traceBegin(TRACE_TAG_PACKAGE_MANAGER, "verifyV3");
        try {
            ApkSignatureSchemeV3Verifier.VerifiedSigner vSigner =
                    ApkSignatureSchemeV3Verifier.verify(apkPath);
            Certificate[][] signerCerts = new Certificate[][] { vSigner.certs };
            Signature[] signerSigs = convertToSignatures(signerCerts);
            Signature[] pastSignerSigs = null;
            int[] pastSignerSigsFlags = null;
            if (vSigner.por != null) {
                // populate proof-of-rotation information
                pastSignerSigs = new Signature[vSigner.por.certs.size()];
                pastSignerSigsFlags = new int[vSigner.por.flagsList.size()];
                for (int i = 0; i < pastSignerSigs.length; i++) {
                    pastSignerSigs[i] = new Signature(vSigner.por.certs.get(i).getEncoded());
                    pastSignerSigsFlags[i] = vSigner.por.flagsList.get(i);
                }
            }
            return new PackageParser.SigningDetails(
                    signerSigs, SignatureSchemeVersion.SIGNING_BLOCK_V3,
                    pastSignerSigs, pastSignerSigsFlags);
```

- 这里会首先尝试v3的签名方案，然后v2v1依次尝试，这里只给出v3的部分，最终返回一个PackageParser类中的内部类SigningDetails的对象
- 检查v3版本签名调用ApkSignatureSchemeV3Verifier类中的verify()方法

### ApkSignatureSchemeV3Verifier.verify()

> frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV3Verifier.java

```java
private static final int APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0;
public static VerifiedSigner verify(String apkFile)
            throws SignatureNotFoundException, SecurityException, IOException {
        return verify(apkFile, true);
    }

    /**
     * Returns the certificates associated with each signer for the given APK without verification.
     * This method is dangerous and should not be used, unless the caller is absolutely certain the
     * APK is trusted.  Specifically, verification is only done for the APK Signature Scheme v3
     * Block while gathering signer information.  The APK contents are not verified.
     *
     * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v3.
     * @throws IOException if an I/O error occurs while reading the APK file.
     */
    public static VerifiedSigner plsCertsNoVerifyOnlyCerts(String apkFile)
            throws SignatureNotFoundException, SecurityException, IOException {
        return verify(apkFile, false);
    }

    private static VerifiedSigner verify(String apkFile, boolean verifyIntegrity)
            throws SignatureNotFoundException, SecurityException, IOException {
        try (RandomAccessFile apk = new RandomAccessFile(apkFile, "r")) {
            return verify(apk, verifyIntegrity);
        }
    }

    /**
     * Verifies APK Signature Scheme v3 signatures of the provided APK and returns the certificates
     * associated with each signer.
     *
     * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v3.
     * @throws SecurityException if an APK Signature Scheme v3 signature of this APK does not
     *         verify.
     * @throws IOException if an I/O error occurs while reading the APK file.
     */
    private static VerifiedSigner verify(RandomAccessFile apk, boolean verifyIntegrity)
            throws SignatureNotFoundException, SecurityException, IOException {
        SignatureInfo signatureInfo = findSignature(apk);
        return verify(apk, signatureInfo, verifyIntegrity);
    }

    /**
     * Returns the APK Signature Scheme v3 block contained in the provided APK file and the
     * additional information relevant for verifying the block against the file.
     *
     * @throws SignatureNotFoundException if the APK is not signed using APK Signature Scheme v3.
     * @throws IOException if an I/O error occurs while reading the APK file.
     */
    private static SignatureInfo findSignature(RandomAccessFile apk)
            throws IOException, SignatureNotFoundException {
        return ApkSigningBlockUtils.findSignature(apk, APK_SIGNATURE_SCHEME_V3_BLOCK_ID);
    }

    /**
     * Verifies the contents of the provided APK file against the provided APK Signature Scheme v3
     * Block.
     *
     * @param signatureInfo APK Signature Scheme v3 Block and information relevant for verifying it
     *        against the APK file.
     */
    private static VerifiedSigner verify(
            RandomAccessFile apk,
            SignatureInfo signatureInfo,
            boolean doVerifyIntegrity) throws SecurityException, IOException {

    }

```


- 通过函数重载，最终的verify()接受三个参数：apk的二进制文件数据对象，一个SignatureInfo对象，是否检查完整性的bool。并返回一个VerifiedSigner的对象
- 其中传递的SignatureInfo对象，是由ApkSigningBlockUtils类中的findSignature()获得
- 可见plsCertsNoVerifyOnlyCerts()与verify()的区别是完整性校验的bool值不同，最终调用的函数殊途同归，这个值最终会判断是否跳过位于ApkSigningBlockUtils类中的verifyIntegrity()方法的校验

所以为了继续分析这个verify()我们先要知道SignatureInfo这个对象是什么

### ApkSigningBlockUtils.findSignature()

> frameworks/base/core/java/android/util/apk/ApkSigningBlockUtils.java

```java
    static SignatureInfo findSignature(RandomAccessFile apk, int blockId)
            throws IOException, SignatureNotFoundException {
        // Find the ZIP End of Central Directory (EoCD) record.
        Pair<ByteBuffer, Long> eocdAndOffsetInFile = getEocd(apk);
        ByteBuffer eocd = eocdAndOffsetInFile.first;
        long eocdOffset = eocdAndOffsetInFile.second;
        if (ZipUtils.isZip64EndOfCentralDirectoryLocatorPresent(apk, eocdOffset)) {
            throw new SignatureNotFoundException("ZIP64 APK not supported");
        }

        // Find the APK Signing Block. The block immediately precedes the Central Directory.
        long centralDirOffset = getCentralDirOffset(eocd, eocdOffset);
        Pair<ByteBuffer, Long> apkSigningBlockAndOffsetInFile =
                findApkSigningBlock(apk, centralDirOffset);
        ByteBuffer apkSigningBlock = apkSigningBlockAndOffsetInFile.first;
        long apkSigningBlockOffset = apkSigningBlockAndOffsetInFile.second;

        // Find the APK Signature Scheme Block inside the APK Signing Block.
        ByteBuffer apkSignatureSchemeBlock = findApkSignatureSchemeBlock(apkSigningBlock,
                blockId);

        return new SignatureInfo(
                apkSignatureSchemeBlock,
                apkSigningBlockOffset,
                centralDirOffset,
                eocdOffset,
                eocd);
    }
```

到这里就已经真的开始对整个apk文件进行检查了，通过获得apk尾部的EOCD块中获得中央目录的偏移，由中央目录开始处往上找24个字节，获取8个字节的小端长整型，这个值即为签名块的长度减8。不过这个长度的值是从签名块开始到中央目录开始，所以这里要从中央目录开始处往前跳转找到签名块的偏移。这里主要看到findApkSigningBlock()，findApkSignatureSchemeBlock()这两个函数

### ApkSigningBlockUtils.findApkSigningBlock()

> frameworks/base/core/java/android/util/apk/ApkSigningBlockUtils.java

```java
    private static final long APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L;
    private static final long APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L;
    private static final int APK_SIG_BLOCK_MIN_SIZE = 32;
    static Pair<ByteBuffer, Long> findApkSigningBlock(
            RandomAccessFile apk, long centralDirOffset)
                    throws IOException, SignatureNotFoundException {
        // FORMAT:
        // OFFSET       DATA TYPE  DESCRIPTION
        // * @+0  bytes uint64:    size in bytes (excluding this field)
        // * @+8  bytes payload
        // * @-24 bytes uint64:    size in bytes (same as the one above)
        // * @-16 bytes uint128:   magic

        if (centralDirOffset < APK_SIG_BLOCK_MIN_SIZE) {
            throw new SignatureNotFoundException(
                    "APK too small for APK Signing Block. ZIP Central Directory offset: "
                            + centralDirOffset);
        }
        // Read the magic and offset in file from the footer section of the block:
        // * uint64:   size of block
        // * 16 bytes: magic
        ByteBuffer footer = ByteBuffer.allocate(24);
        footer.order(ByteOrder.LITTLE_ENDIAN);
        apk.seek(centralDirOffset - footer.capacity());
        apk.readFully(footer.array(), footer.arrayOffset(), footer.capacity());
        if ((footer.getLong(8) != APK_SIG_BLOCK_MAGIC_LO)
                || (footer.getLong(16) != APK_SIG_BLOCK_MAGIC_HI)) {
            throw new SignatureNotFoundException(getLengthPrefixedSlice
                    "No APK Signing Block before ZIP Central Directory");
        }
        // Read and compare size fields
        long apkSigBlockSizeInFooter = footer.getLong(0);
        if ((apkSigBlockSizeInFooter < footer.capacity())
                || (apkSigBlockSizeInFooter > Integer.MAX_VALUE - 8)) {
            throw new SignatureNotFoundException(
                    "APK Signing Block size out of range: " + apkSigBlockSizeInFooter);
        }
        int totalSize = (int) (apkSigBlockSizeInFooter + 8);
        long apkSigBlockOffset = centralDirOffset - totalSize;
        if (apkSigBlockOffset < 0) {
            throw new SignatureNotFoundException(
                    "APK Signing Block offset out of range: " + apkSigBlockOffset);
        }
        ByteBuffer apkSigBlock = ByteBuffer.allocate(totalSize);
        apkSigBlock.order(ByteOrder.LITTLE_ENDIAN);
        apk.seek(apkSigBlockOffset);
        apk.readFully(apkSigBlock.array(), apkSigBlock.arrayOffset(), apkSigBlock.capacity());
        long apkSigBlockSizeInHeader = apkSigBlock.getLong(0);
        if (apkSigBlockSizeInHeader != apkSigBlockSizeInFooter) {
            throw new SignatureNotFoundException(
                    "APK Signing Block sizes in header and footer do not match: "
                            + apkSigBlockSizeInHeader + " vs " + apkSigBlockSizeInFooter);
        }
        return Pair.create(apkSigBlock, apkSigBlockOffset);
    }
```

- 通过中心目录偏移往上16字节找到apk签名的魔术字APK Sig Block 42
- 在往上8字节找到签名块的长度，拿到的长度加8字节为整个签名块的长度
- 从中心目录往上找整个签名块的长度，即为签名块的开始位置
- 函数返回整个签名块的数据，以及签名块开始的偏移

|......|
|:---:|:---:|
|apkSigBlockSizeInHeader (8Byte)|<- apkSigBlockOffset|
|......|
|apkSigBlockSizeInFooter (8Byte)|
|APK_SIG_BLOCK_MAGIC_LO (8Byte)|
|APK_SIG_BLOCK_MAGIC_HI (8Byte)|
|......|<- centralDirOffset|

整个签名块就是从apkSigBlockSizeInHeader到APK_SIG_BLOCK_MAGIC_HI的所有数据

### ApkSigningBlockUtils.findApkSignatureSchemeBlock()

> frameworks/base/core/java/android/util/apk/ApkSigningBlockUtils.java

```java
 static ByteBuffer findApkSignatureSchemeBlock(ByteBuffer apkSigningBlock, int blockId)
            throws SignatureNotFoundException {
        checkByteOrderLittleEndian(apkSigningBlock);
        // FORMAT:
        // OFFSET       DATA TYPE  DESCRIPTION
        // * @+0  bytes uint64:    size in bytes (excluding this field)
        // * @+8  bytes pairs
        // * @-24 bytes uint64:    size in bytes (same as the one above)
        // * @-16 bytes uint128:   magic
        ByteBuffer pairs = sliceFromTo(apkSigningBlock, 8, apkSigningBlock.capacity() - 24);

        int entryCount = 0;
        while (pairs.hasRemaining()) {
            entryCount++;
            if (pairs.remaining() < 8) {
                throw new SignatureNotFoundException(
                        "Insufficient data to read size of APK Signing Block entry #" + entryCount);
            }
            long lenLong = pairs.getLong();
            if ((lenLong < 4) || (lenLong > Integer.MAX_VALUE)) {
                throw new SignatureNotFoundException(
                        "APK Signing Block entry #" + entryCount
                                + " size out of range: " + lenLong);
            }
            int len = (int) lenLong;
            int nextEntryPos = pairs.position() + len;
            if (len > pairs.remaining()) {
                throw new SignatureNotFoundException(
                        "APK Signing Block entry #" + entryCount + " size out of range: " + len
                                + ", available: " + pairs.remaining());
            }
            int id = pairs.getInt();
            if (id == blockId) {
                return getByteBuffer(pairs, len - 4);
            }
            pairs.position(nextEntryPos);
        }

        throw new SignatureNotFoundException(
                "No block with ID " + blockId + " in APK Signing Block.");
    }
```

- 这个函数接受之前解析出的签名部分的数据，通过sliceFromTo剪掉前8个字节和后24个字节
- 利用剩下的部分再次获取八个字节的长度数据，代表着第一个签名部分的长度，一般也只有一个
- 继续获取一个四个字节的id，与blockID进行比较，这个参数来源于ApkSignatureSchemeV3Verifier.verify()函数中传入的常量：APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0 （这个签名块的标记v3v2不同）
- 最终返回的是剪掉签名长度和签名标记数据块

|......|
|:---:|:---:|
|apkSigBlockSizeInHeader (8Byte)|<- apkSigBlockOffset|
|lenLong (8Byte)|
|id (4Byte)|
|apkSignatureSchemeBlock|<- 返回的签名块内容|
|apkSigBlockSizeInFooter (8Byte)|
|APK_SIG_BLOCK_MAGIC_LO (8Byte)|
|APK_SIG_BLOCK_MAGIC_HI (8Byte)|
|......|<- centralDirOffset|


### SignatureInfo.SignatureInfo()

> frameworks/base/core/java/android/util/apk/SignatureInfo.java

```java
class SignatureInfo {
    /** Contents of APK Signature Scheme v2 block. */
    public final ByteBuffer signatureBlock;

    /** Position of the APK Signing Block in the file. */
    public final long apkSigningBlockOffset;

    /** Position of the ZIP Central Directory in the file. */
    public final long centralDirOffset;

    /** Position of the ZIP End of Central Directory (EoCD) in the file. */
    public final long eocdOffset;

    /** Contents of ZIP End of Central Directory (EoCD) of the file. */
    public final ByteBuffer eocd;

    SignatureInfo(ByteBuffer signatureBlock, long apkSigningBlockOffset, long centralDirOffset,
            long eocdOffset, ByteBuffer eocd) {
        this.signatureBlock = signatureBlock;
        this.apkSigningBlockOffset = apkSigningBlockOffset;
        this.centralDirOffset = centralDirOffset;
        this.eocdOffset = eocdOffset;
        this.eocd = eocd;
    }
}

```

最终获取到SignatureInfo包含如下成员：

- APK包含签名信息的数据(signatureBlock)
- APK签名数据块的偏移(apkSigningBlockOffset)
- APK中央目录偏移(centralDirOffset)
- APK中央目录结束块偏移(eocdOffset)
- APK中央目录结束块数据(eocd)

其中重要的就是signatureBlock，就是刚才返回的apkSignatureSchemeBlock，现在可以回到ApkSignatureSchemeV3Verifier.verify()函数

### ApkSignatureSchemeV3Verifier.verify()

> frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV3Verifier.java

```java
 private static VerifiedSigner verify(
            RandomAccessFile apk,
            SignatureInfo signatureInfo,
            boolean doVerifyIntegrity) throws SecurityException, IOException {
        int signerCount = 0;
        Map<Integer, byte[]> contentDigests = new ArrayMap<>();
        VerifiedSigner result = null;
        CertificateFactory certFactory;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to obtain X.509 CertificateFactory", e);
        }
        ByteBuffer signers;
        try {
            signers = getLengthPrefixedSlice(signatureInfo.signatureBlock);
        } catch (IOException e) {
            throw new SecurityException("Failed to read list of signers", e);
        }
        while (signers.hasRemaining()) {
            try {
                ByteBuffer signer = getLengthPrefixedSlice(signers);
                result = verifySigner(signer, contentDigests, certFactory);
                signerCount++;
            } catch (PlatformNotSupportedException e) {
                // this signer is for a different platform, ignore it.
                continue;
            } catch (IOException | BufferUnderflowException | SecurityException e) {
                throw new SecurityException(
                        "Failed to parse/verify signer #" + signerCount + " block",
                        e);
            }
        }

        if (signerCount < 1 || result == null) {
            throw new SecurityException("No signers found");
        }

        if (signerCount != 1) {
            throw new SecurityException("APK Signature Scheme V3 only supports one signer: "
                    + "multiple signers found.");
        }

        if (contentDigests.isEmpty()) {
            throw new SecurityException("No content digests found");
        }

        if (doVerifyIntegrity) {
            ApkSigningBlockUtils.verifyIntegrity(contentDigests, apk, signatureInfo);
        }

        if (contentDigests.containsKey(CONTENT_DIGEST_VERITY_CHUNKED_SHA256)) {
            byte[] verityDigest = contentDigests.get(CONTENT_DIGEST_VERITY_CHUNKED_SHA256);
            result.verityRootHash = ApkSigningBlockUtils.parseVerityDigestAndVerifySourceLength(
                    verityDigest, apk.length(), signatureInfo);
        }

        return result;
    }
```

- 这里首先生成了一个certFactory对象，证书标准为X.509
- 构造一个空的contentDigests，准备存放签名块中的完整性校验信息
- 通过getLengthPrefixedSlice()函数剪掉signatureBlock（刚才获得的签名数据块）两个四字节的长度数据，获得signer数据块

这里我们发现当我们尝试获取一个大数据块中的小数据块时候总是有如下的代码写法：

```java
		try {
            signers = getLengthPrefixedSlice(signatureInfo.signatureBlock);
        } catch (IOException e) {}

        while (signers.hasRemaining()) {
            try {
                ByteBuffer signer = getLengthPrefixedSlice(signers);
            } catch (PlatformNotSupportedException e) {}
        }

```

这其实是一种带长度前缀的数据块的构造方法，而且是为了一个大块下可以包含多个字块。第一个try是通过块前长度获取整个块，第二个在循环里的try是通过每一个字块长度获得每一个字块，但是这里一般签名块不存在并列，所以一般早签名块前就会有两个长度标记，第一个比第二个数值大4。

|......|
|:---:|:---:|
|apkSigBlockSizeInHeader (8Byte)|<- apkSigBlockOffset|
|lenLong (8Byte)|
|id (4Byte)|
|signersLength (4Byte)|
|signerLength (4Byte)|
|signer|<- 传入verifySigner()的数据
|apkSigBlockSizeInFooter (8Byte)|
|APK_SIG_BLOCK_MAGIC_LO (8Byte)|
|APK_SIG_BLOCK_MAGIC_HI (8Byte)|
|......|<- centralDirOffset|

最终将signer部分数据传入verifySigner()函数

### ApkSignatureSchemeV3Verifier.verifySigner()

这个函数虽然比较长，但是这里正是校验签名真正的实现部分，所以我们分段来分析：


> frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV3Verifier.java

```java
    private static VerifiedSigner verifySigner(
            ByteBuffer signerBlock,
            Map<Integer, byte[]> contentDigests,
            CertificateFactory certFactory)
            throws SecurityException, IOException, PlatformNotSupportedException {
        ByteBuffer signedData = getLengthPrefixedSlice(signerBlock);
        int minSdkVersion = signerBlock.getInt();
        int maxSdkVersion = signerBlock.getInt();

        if (Build.VERSION.SDK_INT < minSdkVersion || Build.VERSION.SDK_INT > maxSdkVersion) {
            // this signature isn't meant to be used with this platform, skip it.
            throw new PlatformNotSupportedException(
                    "Signer not supported by this platform "
                    + "version. This platform: " + Build.VERSION.SDK_INT
                    + ", signer minSdkVersion: " + minSdkVersion
                    + ", maxSdkVersion: " + maxSdkVersion);
        }

        ByteBuffer signatures = getLengthPrefixedSlice(signerBlock);
        byte[] publicKeyBytes = readLengthPrefixedByteArray(signerBlock);

```

这里将传入的signer部分数据继续拆分，主要是三个部分：

- signedData
- signatures
- publicKeyBytes

具体如下：

|singer|
|:---:|
|signedDataLength (8Byte)|
|signedData|
|......|
|......|
|minSdkVersion (4Byte)|
|maxSdkVersion (4Byte)|
|signaturesLength (4Byte)|
|signatures|
|......|
|......|
|publicKeyBytesLength(8Byte)|
|publicKeyBytes(byte[])|
|......|
|......|

回到函数继续分析：

```java
        int signatureCount = 0;
        int bestSigAlgorithm = -1;
        byte[] bestSigAlgorithmSignatureBytes = null;
        List<Integer> signaturesSigAlgorithms = new ArrayList<>();
        while (signatures.hasRemaining()) {
            signatureCount++;
            try {
                ByteBuffer signature = getLengthPrefixedSlice(signatures);
                if (signature.remaining() < 8) {
                    throw new SecurityException("Signature record too short");
                }
                int sigAlgorithm = signature.getInt();
                signaturesSigAlgorithms.add(sigAlgorithm);
                if (!isSupportedSignatureAlgorithm(sigAlgorithm)) {
                    continue;
                }
                if ((bestSigAlgorithm == -1)
                        || (compareSignatureAlgorithm(sigAlgorithm, bestSigAlgorithm) > 0)) {
                    bestSigAlgorithm = sigAlgorithm;
                    bestSigAlgorithmSignatureBytes = readLengthPrefixedByteArray(signature);
                }
            } catch (IOException | BufferUnderflowException e) {
                throw new SecurityException(
                        "Failed to parse signature record #" + signatureCount,
                        e);
            }
        }
        if (bestSigAlgorithm == -1) {
            if (signatureCount == 0) {
                throw new SecurityException("No signatures found");
            } else {
                throw new SecurityException("No supported signatures found");
            }
        }
```

这段就是继续拆分signatures块，分出四个字节的sigAlgorithm与加密过的hash值bestSigAlgorithmSignatureBytes

|singer|
|:---:|
|signedDataLength (8Byte)|
|signedData|
|......|
|......|
|minSdkVersion (4Byte)|
|maxSdkVersion (4Byte)|
|signaturesLength (4Byte)|
|signatureLength (4Byte)|
|sigAlgorithm (4Byte)|
|bestSigAlgorithmSignatureBytesLength (4Byte)|
|bestSigAlgorithmSignatureBytes (Byte[])|
|publicKeyBytesLength(8Byte)|
|publicKeyBytes(byte[])|
|......|
|......|

```java
        String keyAlgorithm = getSignatureAlgorithmJcaKeyAlgorithm(bestSigAlgorithm);
        Pair<String, ? extends AlgorithmParameterSpec> signatureAlgorithmParams =
                getSignatureAlgorithmJcaSignatureAlgorithm(bestSigAlgorithm);
        String jcaSignatureAlgorithm = signatureAlgorithmParams.first;
        AlgorithmParameterSpec jcaSignatureAlgorithmParams = signatureAlgorithmParams.second;
        boolean sigVerified;
        try {
            PublicKey publicKey =
                    KeyFactory.getInstance(keyAlgorithm)
                            .generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            Signature sig = Signature.getInstance(jcaSignatureAlgorithm);
            sig.initVerify(publicKey);
            if (jcaSignatureAlgorithmParams != null) {
                sig.setParameter(jcaSignatureAlgorithmParams);
            }
            sig.update(signedData);
            sigVerified = sig.verify(bestSigAlgorithmSignatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException
                | InvalidAlgorithmParameterException | SignatureException e) {
            throw new SecurityException(
                    "Failed to verify " + jcaSignatureAlgorithm + " signature", e);
        }
        if (!sigVerified) {
            throw new SecurityException(jcaSignatureAlgorithm + " signature did not verify");
        }

        // Signature over signedData has verified.
```

用最后的公钥，中间的hash，验证前面的SignatureData：即公钥解密中间的hash，并计算SignatureData的hash进行比对

```java
        byte[] contentDigest = null;
        signedData.clear();
        ByteBuffer digests = getLengthPrefixedSlice(signedData);
        List<Integer> digestsSigAlgorithms = new ArrayList<>();
        int digestCount = 0;
        while (digests.hasRemaining()) {
            digestCount++;
            try {
                ByteBuffer digest = getLengthPrefixedSlice(digests);
                if (digest.remaining() < 8) {
                    throw new IOException("Record too short");
                }
                int sigAlgorithm = digest.getInt();
                digestsSigAlgorithms.add(sigAlgorithm);
                if (sigAlgorithm == bestSigAlgorithm) {
                    contentDigest = readLengthPrefixedByteArray(digest);
                }
            } catch (IOException | BufferUnderflowException e) {
                throw new IOException("Failed to parse digest record #" + digestCount, e);
            }
        }

        if (!signaturesSigAlgorithms.equals(digestsSigAlgorithms)) {
            throw new SecurityException(
                    "Signature algorithms don't match between digests and signatures records");
        }
        int digestAlgorithm = getSignatureAlgorithmContentDigestAlgorithm(bestSigAlgorithm);
        byte[] previousSignerDigest = contentDigests.put(digestAlgorithm, contentDigest);
        if ((previousSignerDigest != null)
                && (!MessageDigest.isEqual(previousSignerDigest, contentDigest))) {
            throw new SecurityException(
                    getContentDigestAlgorithmJcaDigestAlgorithm(digestAlgorithm)
                    + " contents digest does not match the digest specified by a preceding signer");
        }

        ByteBuffer certificates = getLengthPrefixedSlice(signedData);
        List<X509Certificate> certs = new ArrayList<>();
        int certificateCount = 0;
        while (certificates.hasRemaining()) {
            certificateCount++;
            byte[] encodedCert = readLengthPrefixedByteArray(certificates);
            X509Certificate certificate;
            try {
                certificate = (X509Certificate)
                        certFactory.generateCertificate(new ByteArrayInputStream(encodedCert));
            } catch (CertificateException e) {
                throw new SecurityException("Failed to decode certificate #" + certificateCount, e);
            }
            certificate = new VerbatimX509Certificate(
                    certificate, encodedCert);
            certs.add(certificate);
        }

        if (certs.isEmpty()) {
            throw new SecurityException("No certificates listed");
        }
        X509Certificate mainCertificate = certs.get(0);
        byte[] certificatePublicKeyBytes = mainCertificate.getPublicKey().getEncoded();
        if (!Arrays.equals(publicKeyBytes, certificatePublicKeyBytes)) {
            throw new SecurityException(
                    "Public key mismatch between certificate and signature record");
        }

        int signedMinSDK = signedData.getInt();
        if (signedMinSDK != minSdkVersion) {
            throw new SecurityException(
                    "minSdkVersion mismatch between signed and unsigned in v3 signer block.");
        }

        int signedMaxSDK = signedData.getInt();
        if (signedMaxSDK != maxSdkVersion) {
            throw new SecurityException(
                    "maxSdkVersion mismatch between signed and unsigned in v3 signer block.");
        }

        ByteBuffer additionalAttrs = getLengthPrefixedSlice(signedData);
        return verifyAdditionalAttributes(additionalAttrs, certs, certFactory);
    }
```

继续拆分块，并在拆分过程中校验数据是否匹配：

|singer|
|:---:|
|signedDataLength (8Byte)|
|digestsLength (4Byte)|
|digestLength (4Byte)|
|sigAlgorithm (4Byte)|
|contentDigestLength (4Byte)|
|contentDigest (Byte[])
|certificatesLength (4Byte)|
|encodedCertLength (4Byte)|
|encodedCert (byte[])|
|signedMinSDK (4Byte)|
|signedMaxSDK (4Byte)|
|additionalAttrsLength (4Byte)|
|additionalAttrs|<-v3版本签名新特性|
|minSdkVersion (4Byte)|
|maxSdkVersion (4Byte)|
|signaturesLength (4Byte)|
|signatureLength (4Byte)|
|sigAlgorithm (4Byte)|
|bestSigAlgorithmSignatureBytesLength (4Byte)|
|bestSigAlgorithmSignatureBytes (Byte[])|
|publicKeyBytesLength(8Byte)|
|publicKeyBytes(byte[])|

这里解析出证书，添加到certs列表里，并做了一系列的校验，校验signedData中解析的数据，与其他块中的数据是否相匹配：

- signedData块中的sigAlgorithm，与signatures块中的sigAlgorithm
- signedMinSDK与minSdkVersion
- signedMaxSDK与maxSdkVersion
- encodedCert解析出的公钥与整个签名块尾部个公钥

其中拆分出的additionalAttrs就是v3版本中新添加的一个数据块，继续下一个函数

### ApkSignatureSchemeV3Verifier.verifyAdditionalAttributes()

> frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV3Verifier.java

```java
    private static final int PROOF_OF_ROTATION_ATTR_ID = 0x3ba06f8c;
    private static VerifiedSigner verifyAdditionalAttributes(ByteBuffer attrs,
            List<X509Certificate> certs, CertificateFactory certFactory) throws IOException {
        X509Certificate[] certChain = certs.toArray(new X509Certificate[certs.size()]);
        VerifiedProofOfRotation por = null;

        while (attrs.hasRemaining()) {
            ByteBuffer attr = getLengthPrefixedSlice(attrs);
            if (attr.remaining() < 4) {
                throw new IOException("Remaining buffer too short to contain additional attribute "
                        + "ID. Remaining: " + attr.remaining());
            }
            int id = attr.getInt();
            switch(id) {
                case PROOF_OF_ROTATION_ATTR_ID:
                    if (por != null) {
                        throw new SecurityException("Encountered multiple Proof-of-rotation records"
                                + " when verifying APK Signature Scheme v3 signature");
                    }
                    por = verifyProofOfRotationStruct(attr, certFactory);
                    // make sure that the last certificate in the Proof-of-rotation record matches
                    // the one used to sign this APK.
                    try {
                        if (por.certs.size() > 0
                                && !Arrays.equals(por.certs.get(por.certs.size() - 1).getEncoded(),
                                        certChain[0].getEncoded())) {
                            throw new SecurityException("Terminal certificate in Proof-of-rotation"
                                    + " record does not match APK signing certificate");
                        }
                    } catch (CertificateEncodingException e) {
                        throw new SecurityException("Failed to encode certificate when comparing"
                                + " Proof-of-rotation record and signing certificate", e);
                    }

                    break;
                default:
                    // not the droid we're looking for, move along, move along.
                    break;
            }
        }
        return new VerifiedSigner(certChain, por);
    }

```

继续拆分attrs，就是上一个函数传入的additionalAttrs，把减去一个长度和魔术字的数据块attr继续丢进下一个函数verifyProofOfRotationStruct获得por这个变量，最后返回一个VerifiedSigner

### ApkSignatureSchemeV3Verifier.verifyProofOfRotationStruct()

> frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV3Verifier.java

```java
private static VerifiedProofOfRotation verifyProofOfRotationStruct(
            ByteBuffer porBuf,
            CertificateFactory certFactory)
            throws SecurityException, IOException {
        int levelCount = 0;
        int lastSigAlgorithm = -1;
        X509Certificate lastCert = null;
        List<X509Certificate> certs = new ArrayList<>();
        List<Integer> flagsList = new ArrayList<>();

        // Proof-of-rotation struct:
        // A uint32 version code followed by basically a singly linked list of nodes, called levels
        // here, each of which have the following structure:
        // * length-prefix for the entire level
        //     - length-prefixed signed data (if previous level exists)
        //         * length-prefixed X509 Certificate
        //         * uint32 signature algorithm ID describing how this signed data was signed
        //     - uint32 flags describing how to treat the cert contained in this level
        //     - uint32 signature algorithm ID to use to verify the signature of the next level. The
        //         algorithm here must match the one in the signed data section of the next level.
        //     - length-prefixed signature over the signed data in this level.  The signature here
        //         is verified using the certificate from the previous level.
        // The linking is provided by the certificate of each level signing the one of the next.

        try {

            // get the version code, but don't do anything with it: creator knew about all our flags
            porBuf.getInt();
            while (porBuf.hasRemaining()) {
                levelCount++;
                ByteBuffer level = getLengthPrefixedSlice(porBuf);
                ByteBuffer signedData = getLengthPrefixedSlice(level);
                int flags = level.getInt();
                int sigAlgorithm = level.getInt();
                byte[] signature = readLengthPrefixedByteArray(level);

                if (lastCert != null) {
                    // Use previous level cert to verify current level
                    Pair<String, ? extends AlgorithmParameterSpec> sigAlgParams =
                            getSignatureAlgorithmJcaSignatureAlgorithm(lastSigAlgorithm);
                    PublicKey publicKey = lastCert.getPublicKey();
                    Signature sig = Signature.getInstance(sigAlgParams.first);
                    sig.initVerify(publicKey);
                    if (sigAlgParams.second != null) {
                        sig.setParameter(sigAlgParams.second);
                    }
                    sig.update(signedData);
                    if (!sig.verify(signature)) {
                        throw new SecurityException("Unable to verify signature of certificate #"
                                + levelCount + " using " + sigAlgParams.first + " when verifying"
                                + " Proof-of-rotation record");
                    }
                }

                signedData.rewind();
                byte[] encodedCert = readLengthPrefixedByteArray(signedData);
                int signedSigAlgorithm = signedData.getInt();
                if (lastCert != null && lastSigAlgorithm != signedSigAlgorithm) {
                    throw new SecurityException("Signing algorithm ID mismatch for certificate #"
                            + levelCount + " when verifying Proof-of-rotation record");
                }
                lastCert = (X509Certificate)
                        certFactory.generateCertificate(new ByteArrayInputStream(encodedCert));
                lastCert = new VerbatimX509Certificate(lastCert, encodedCert);

                lastSigAlgorithm = sigAlgorithm;
                certs.add(lastCert);
                flagsList.add(flags);
            }
        } catch (IOException | BufferUnderflowException e) {
            throw new IOException("Failed to parse Proof-of-rotation record", e);
        } catch (NoSuchAlgorithmException | InvalidKeyException
                | InvalidAlgorithmParameterException | SignatureException e) {
            throw new SecurityException(
                    "Failed to verify signature over signed data for certificate #"
                            + levelCount + " when verifying Proof-of-rotation record", e);
        } catch (CertificateException e) {
            throw new SecurityException("Failed to decode certificate #" + levelCount
                    + " when verifying Proof-of-rotation record", e);
        }
        return new VerifiedProofOfRotation(certs, flagsList);
    }
```

这里的注释已经详细的给出了v3新特性的中Proof-of-rotation的结构说明，图示如下：

|ProofOfRotationStruct|
|:---:|
|version code (4Byte)|
|levelLength (4Byte)|<- level 0|
|signedDataLength (4Byte)|
|encodedCertLength (4Byte)|
|encodedCert (Byte[])|
|signedSigAlgorithm (4Byte)|
|flags (4Byte)|
|sigAlgorithm (4Byte)|
|signatureLength (4Byte)|
|signature (Byte[])|
|levelLength (4Byte)|<- level 1|
|signedDataLength (4Byte)|
|encodedCertLength (4Byte)|
|encodedCert (Byte[])|
|signedSigAlgorithm (4Byte)|
|flags (4Byte)|
|sigAlgorithm (4Byte)|
|signatureLength (4Byte)|
|signature (Byte[])|
|levelLength (4Byte)|<- level 2|
|......|
|......|
|......|


这里其实就是一个证书链的验证：

- 利用level 0证书中的公钥去验证level 1的数据
- 同理level 1证书中的公钥去验证level 2的数据
- 若最后的证书是level 2，则保证整个签名的证书需与level 2匹配

即如果我们想换新证书的时候，需要在por中添加最老的证书为level 0，利用最老的证书去保证新的证书，然后在利用新的证书签名即可。这个函数最终会返回VerifiedProofOfRotation对象，即之前将赋值给por的对象，参数为证书列表和标记列表。

### ApkSignatureSchemeV3Verifier.VerifiedProofOfRotation()

> frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV3Verifier.java

```java
    public static class VerifiedProofOfRotation {
        public final List<X509Certificate> certs;
        public final List<Integer> flagsList;

        public VerifiedProofOfRotation(List<X509Certificate> certs, List<Integer> flagsList) {
            this.certs = certs;
            this.flagsList = flagsList;
        }
    }
```

就是一个成员是两个列表的类，返回到verifyAdditionalAttributes()函数，这个函数就是验证了，por中最后的证书是否匹配我们签名整个apk包的证书，最后返回VerifiedSigner(certChain, por)，第一个参数里就一个证书，第二个参数里有一个证书链

### ApkSignatureSchemeV3Verifier.VerifiedSigner()

> frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV3Verifier.java

```JAVA
    public static class VerifiedSigner {
        public final X509Certificate[] certs;
        public final VerifiedProofOfRotation por;

        public byte[] verityRootHash;

        public VerifiedSigner(X509Certificate[] certs, VerifiedProofOfRotation por) {
            this.certs = certs;
            this.por = por;
        }

    }
```

就是把传进来的两个参数放入成员变量中，回到ApkSignatureSchemeV3Verifier.verify()函数中，最终的返回值赋给result这个变量里，不过在返回result之前，因为没有跳过完整性检查doVerifyIntegrity，这个值为真所以继续执行ApkSigningBlockUtils.verifyIntegrity()这个函数，这个完整性检查与v2版本完全相同，就是将apk文件分段分成1M大小的数据然后hash，比较的数据已经通过verifySigner()函数解析出来了，就是contentDigests。继续这个函数的深入分析先留白。

### ApkSigningBlockUtils.verifyIntegrity()

> frameworks/base/core/java/android/util/apk/ApkSigningBlockUtils.java

检查完毕从ApkSignatureSchemeV3Verifier.verify()返回result到ApkSignatureVerifier.verify()

### ApkSignatureVerifier.verify()

> frameworks/base/core/java/android/util/apk/ApkSignatureVerifier.java

```java
 try {
            ApkSignatureSchemeV3Verifier.VerifiedSigner vSigner =
                    ApkSignatureSchemeV3Verifier.verify(apkPath);
            Certificate[][] signerCerts = new Certificate[][] { vSigner.certs };
            Signature[] signerSigs = convertToSignatures(signerCerts);
            Signature[] pastSignerSigs = null;
            int[] pastSignerSigsFlags = null;
            if (vSigner.por != null) {
                // populate proof-of-rotation information
                pastSignerSigs = new Signature[vSigner.por.certs.size()];
                pastSignerSigsFlags = new int[vSigner.por.flagsList.size()];
                for (int i = 0; i < pastSignerSigs.length; i++) {
                    pastSignerSigs[i] = new Signature(vSigner.por.certs.get(i).getEncoded());
                    pastSignerSigsFlags[i] = vSigner.por.flagsList.get(i);
                }
            }
            return new PackageParser.SigningDetails(
                    signerSigs, SignatureSchemeVersion.SIGNING_BLOCK_V3,
                    pastSignerSigs, pastSignerSigsFlags);
```

这里可以看出我们最后的por证书链信息放到了返回的SigningDetails中的pastSignerSigs, pastSignerSigsFlags与成员中。最后会把这个变量赋值给pkg.mSigningDetails，返回到PMS

### PackageManagerService.InstallPackageLI()

> frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java

```java
 if (bp != null) {
                    // If the defining package is signed with our cert, it's okay.  This
                    // also includes the "updating the same package" case, of course.
                    // "updating same package" could also involve key-rotation.
                    final boolean sigsOk;
                    final String sourcePackageName = bp.getSourcePackageName();
                    final PackageSettingBase sourcePackageSetting = bp.getSourcePackageSetting();
                    final KeySetManagerService ksms = mSettings.mKeySetManagerService;
                    if (sourcePackageName.equals(pkg.packageName)
                            && (ksms.shouldCheckUpgradeKeySetLocked(
                                    sourcePackageSetting, scanFlags))) {
                        sigsOk = ksms.checkUpgradeKeySetLocked(sourcePackageSetting, pkg);
                    } else {

                        // in the event of signing certificate rotation, we need to see if the
                        // package's certificate has rotated from the current one, or if it is an
                        // older certificate with which the current is ok with sharing permissions
                        if (sourcePackageSetting.signatures.mSigningDetails.checkCapability(
                                        pkg.mSigningDetails,
                                        PackageParser.SigningDetails.CertCapabilities.PERMISSION)) {
                            sigsOk = true;
                        } else if (pkg.mSigningDetails.checkCapability(
                                        sourcePackageSetting.signatures.mSigningDetails,
                                        PackageParser.SigningDetails.CertCapabilities.PERMISSION)) {

                            // the scanned package checks out, has signing certificate rotation
                            // history, and is newer; bring it over
                            sourcePackageSetting.signatures.mSigningDetails = pkg.mSigningDetails;
                            sigsOk = true;
                        } else {
                            sigsOk = false;
                        }
                    }
```

这里首先通过包名获取到包的设置信息，如果不为空则证明已经安装过这个应用，过了一堆判断最终进入checkCapability()函数信，新的签名和老的签名信息互相检查，如果是第一次安装则不会对证书进行进一步的检查

### PackageParser.SigningDetails.checkCapability()

> frameworks/base/core/java/android/content/pm/PackageParser.java

```java
        public boolean checkCapability(SigningDetails oldDetails, @CertCapabilities int flags) {
            if (this == UNKNOWN || oldDetails == UNKNOWN) {
                return false;
            }
            if (oldDetails.signatures.length > 1) {

                // multiple-signer packages cannot rotate signing certs, so we must have an exact
                // match, which also means all capabilities are granted
                return signaturesMatchExactly(oldDetails);
            } else {

                // we may have signing certificate rotation history, check to see if the oldDetails
                // was one of our old signing certificates, and if we grant it the capability it's
                // requesting
                return hasCertificate(oldDetails.signatures[0], flags);
            }
        }
```

根据注释可以看出，如果是多签名的则不被允许使用新特性。最终进入hasCertificate()函数

### PackageParser.SigningDetails.hasCertificate()

> frameworks/base/core/java/android/content/pm/PackageParser.java

```java
 public boolean hasCertificate(Signature signature, @CertCapabilities int flags) {
            return hasCertificateInternal(signature, flags);
        }

        /** Convenient wrapper for calling {@code hasCertificate} with certificate's raw bytes. */
        public boolean hasCertificate(byte[] certificate) {
            Signature signature = new Signature(certificate);
            return hasCertificate(signature);
        }

        private boolean hasCertificateInternal(Signature signature, int flags) {
            if (this == UNKNOWN) {
                return false;
            }

            // only single-signed apps can have pastSigningCertificates
            if (hasPastSigningCertificates()) {

                // check all past certs, except for the current one, which automatically gets all
                // capabilities, since it is the same as the current signature
                for (int i = 0; i < pastSigningCertificates.length - 1; i++) {
                    if (pastSigningCertificates[i].equals(signature)) {
                        if (flags == PAST_CERT_EXISTS
                                || (flags & pastSigningCertificatesFlags[i]) == flags) {
                            return true;
                        }
                    }
                }
            }

            // not in previous certs signing history, just check the current signer and make sure
            // we are singly-signed
            return signatures.length == 1 && signatures[0].equals(signature);
        }

```

即验证现在签名的证书是否在以前的包信息中的证书中以及por证书列表中存在过，如果存在则返回真，即认证通过。返回到PMS继续安装，至此为止整个校验签名的流程就大致分析完毕


## 参考

[分析 Android V2 新签名打包机制](https://cloud.tencent.com/developer/article/1006237)

[Android中签名、证书、公钥密钥的概念及使用](https://blog.csdn.net/u011974987/article/details/52415037)

[一文弄懂关于证书的一切，ssl协议，android包签名机制](https://blog.csdn.net/dreamytian/article/details/79687854)

[Android签名机制之---签名验证过程详解](https://blog.csdn.net/jiangwei0910410003/article/details/50443505)
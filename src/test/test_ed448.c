/*
 * Unit tests of ed448.c (Ed448 on the nat library).
 * The expected results come from a simple implementation in Python
 * (affine coordinates, Python integers).
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "nat.h"
#include "ec_common.h"
#include "ed448.h"

#if defined(TEST_BMI2_ADX)
#include <stdio.h>
#include <cpuid.h>

static int have_bmi2_adx(void)
{
    unsigned eax, ebx, ecx, edx;

    if (__get_cpuid_max(0, NULL) < 7)
        return 0;
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx & (1U << 8)) && (ebx & (1U << 19));
}
#endif

/* Private functions (they are not static when STATIC is defined as empty) */
uint64_t ed448_on_curve(EcWs *ws, const Ed448Context *ctx, const uint64_t *x, const uint64_t *y, const uint64_t *z);

typedef struct {
    int base;                       /* 0: G, 1: Q, 2: Q + T (T of order 4) */
    const char *k;
    const char *rx, *ry;
} TestCase;

static const char *gx = "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e";
static const char *gy = "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14";
/* p + 1 = 2^448 - 2^224 */
static const char *p_plus_1 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000";

static const char *qx = "4f6b66e4538eb23c556a046fb24fa2cca13292ea78378dfb7248a9420f58df6b0ad2ebbfbeb44980dc711452aa7988a13344c15b1c1eb88b";
static const char *qy = "95644fa91fa5f7366b3aa03b0c1d16d027fb1a042b1fb41e1179d5c5b6143a9584f3e7fffdabf22e154ccbb750ed65a3020aff88b4557bcb";
static const char *qtx = "95644fa91fa5f7366b3aa03b0c1d16d027fb1a042b1fb41e1179d5c5b6143a9584f3e7fffdabf22e154ccbb750ed65a3020aff88b4557bcb";
static const char *qty = "b094991bac714dc3aa95fb904db05d335ecd6d1587c872048db756bcf0a72094f52d1440414bb67f238eebad5586775eccbb3ea4e3e14774";
static const TestCase cases[] = {
    { 0, "0", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" },
    { 0, "1", "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e", "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14" },
    { 0, "2", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555", "ae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed" },
    { 0, "3", "0865886b9108af6455bd64316cb6943332241b8b8cda82c7e2ba077a4a3fcfe8daa9cbf7f6271fd6e862b769465da8575728173286ff2f8f", "e005a8dbd5125cf706cbda7ad43aa6449a4a8d952356c3b9fce43c82ec4e1d58bb3a331bdb6767f0bffa9a68fed02dafb822ac13588ed6fc" },
    { 0, "4", "49dcbc5c6c0cce2c1419a17226f929ea255a09cf4e0891c693fda4be70c74cc301b7bdf1515dd8ba21aee1798949e120e2ce42ac48ba7f30", "d49077e4accde527164b33a5de021b979cb7c02f0457d845c90dc3227b8a5bc1c0d8f97ea1ca9472b5d444285d0d4f5b32e236f86de51839" },
    { 0, "10", "dd8402f36c2e9f966e9290104c4f302de8a918066e09d5dd6f5b419ec49f9eeafd74c278d5b37ed68c9c6300b41a07768fedb5fbc9120262", "1ab2b2d015957671740ab813879afefaf0a16acd03fb9c2b9a0193724ab9942646bc0936d4edc83158ef53c0ed47ca820ccde6ec861d7985" },
    { 0, "11", "1acd0638845a9599fa9249c0d5e499cd1394696e609f6c5c97c356586cf132c9f3bf2a765ddff481935da96e5d65beb9dc1e461731649b68", "7ba7c6db3cd4fad6fcaef48cb82f8aa400400e4a884ef1357e32c8fdfd6c8a2dc8102820afc5f6161967ea20e78ea17b7f0b065413636087" },
    { 0, "1f", "f6448e35bd894657fa24cc96b98002a58a9b7d104a897fcbd5660894eb2037a489396bc0545d85a1aedb1356e538df4afb16539fc1bdd30d", "2fb4e0751d99cf407ed73a7d687b4891ff359e6831174332220da22be0ffa44bd0800995141939e66b2110fa274992cfc6ee727418805c83" },
    { 0, "20", "745d3d448b2289b6717909b541986de74408125612abf7fb9b0e0743dcb5b3030d90c8f560809dc43c3d28766d1716c675c5b004f069d31a", "59dd6be767914ab19625d85956b7099dbc0b0d92d2ebbf37d2132166c5c51fef4393307152d429277a90e8b549b5ad178834c327b3aa95c8" },
    { 0, "21", "af43becc7ff796344e49517df43a9e85c2c408d2a72bb046211b3e22d039042595afb87664623b1f2b3297465a7806e58528fe9a19fddd5c", "d24e162932cfa4db70deb638afa8eef29d40f4b1d8981a64decbb56243576142f3d6dbe6a0b13ff05f9b4fc7aaf16ed146dc0a8bcd4ebc11" },
    { 0, "103", "f0527bf11a69e3781056ee3ff2403333c70db1c7e3f86f33b1db5df351470c743cb11881654a5abf5a082b68ec2abbbc3c9c57117343a460", "e4dd353d83d2497164a553291ce291754aae355d5187796da155df49fe4d9e1e2fcf50651e733b1f8a7251cd2d631ddb642d4cb75922a4c5" },
    { 0, "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2", "b0e68f399412f212dde2ea59dd40c92561eb9a8fb8f0e89815921cda5c2c5b9bed51e508d5499aeebcc47f1e74ff6c71d9d957d438f33fa1", "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14" },
    { 0, "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" },
    { 0, "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f4", "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e", "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14" },
    { 0, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffdf3288fa7113b6d26bb58da4085b309ca37163d548de30a4aad6113cc", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" },
    { 0, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffdf3288fa7113b6d26bb58da4085b309ca37163d548de30a4aad6113cd", "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e", "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14" },
    { 0, "340d550056a420245ad29d36b71e08de500b9ac958e330b1821b4a5bf6c522caee1a36a6c7fc64c1315631d29ee1faf4d4f9ce4c1e09e2d4", "92a68b0d7aa8ce4d56afe8ef9fc094ce48a276ed33be360c10f70a8726e90d56c520730582adaf2c04354b5cc66125d168a60f2294e804df", "f9d2cb3f0ea0b99eee6cd0ccc2c654297fe1413950bfd0668385810e9a89d2a13bc507a1bb17d7effe7222c3f15eca2cc0cc38807d84b897" },
    { 0, "c59e8e6f582d396bce72a5dd68933b5c5b68f079f8766f193ce98fc98d521b0fdc5a58aa4e54fe18e75592ec783096eace0d9682f457da87", "1686e9aed804c5d75b771bfc5b7df34addb84cb285f522c1b89886e877afa61305517109b3431888e6c2b1996b65ba4fe3cfb94d0b784672", "240205cf5730ede1dfe03dee95f876c32d381cb8f9d8f7409f94691195baf8be9d6abc56776a0c837f6c0b9833946f81b89aedbd4d82231e" },
    { 0, "5a48fcd486018292e2c95480d0f97b1d31b7efad4bbbb7d1c80fbbf428da2d87c4bf6dd2099b6de4bfce39fecf885299dc1e526f63fd97eba5", "5eb342c078beef54dfbf64bd7ec8829bdbd58abdfff7703f1a33f4f8b0e1249c6d5bfe598734108de9f01d7a1b78054a953010b1627ecff7", "62e84b5512e6f4be846f86c47d50ad360fb2bf5df9f7ee71cf1ad6e9ea6d124a8c1cda1817b308acbf76a1c2ed5fdec55104cd4df8da6647" },
    { 0, "46225e2619867e8fa57147eae1eedbbb888cc22d40a59a3606aa12e140d8239ac76f52b375223cfa7fe0c202307f0e83be074baf3b6639ef299a39cbfc8d019b21021930d8fda3fcd6918e", "7d667aab3e24b5b317d355ac6d43a13cccc39f46157251112afc8054fe71a382c6c4f8567cecbd40cc2e3590f21dfbc76fb49ef13cce79cd", "e459e290223323674336f1b0ce6d85120eb571a4cccaa36db9f0dbbfae462fa0bab128d4419861baa5136ef6a1107c3e8bf216edde3ad5b3" },
    { 1, "0", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" },
    { 1, "1", "4f6b66e4538eb23c556a046fb24fa2cca13292ea78378dfb7248a9420f58df6b0ad2ebbfbeb44980dc711452aa7988a13344c15b1c1eb88b", "95644fa91fa5f7366b3aa03b0c1d16d027fb1a042b1fb41e1179d5c5b6143a9584f3e7fffdabf22e154ccbb750ed65a3020aff88b4557bcb" },
    { 1, "2", "d25825a1161d2615250ae04eba00bdae75dd0f0d135ecfc5bdd14563c85b88764d3f22fc36de64c0c88fd9fdcec6e814ee94b8aa53965f32", "775c1b13213324012d43606c47c18a20b05ccaf302db20d3e56b7d79c4e909fc1d70a0aece4a70b97c4b6169c4cf554025c5a080bad69b18" },
    { 1, "3", "5789a6c837456ddc016b54a3020cea12bbba5eb334373201e791c71f43f90e389c0aab78166095ce6c5f27876de7d6f99d402de82c0020c4", "93b7703c01376fb6edb9c37f3a3d5180609f62e9dbd63ac33393ff0f814f8bdc08bc980699a581c126bf68b47b6023ea2b28e4c4a2cfdbde" },
    { 1, "4", "e0b605b6915818a60751094058d941207298928129ac75ae2e7d6b24954618ecb00aa8851c116c941928f8a51d9ac268d45fd2d950943f48", "659fffd8c6fa6df84dc033c219a30e391b9808c2c2b0b5dd5039e50fb7545556feb404cefd3dfe9f66b8cdd98d5cb0933e6ec63e5fd3fcfd" },
    { 1, "10", "827109368a89385a087355ad6823918ed77d1fad5750792f81a8ce915c2bd283bf6e449a11e8f632f3f6c109c6d1eedcb59111f3849a80d5", "e4defac8d03d48c58d468cf530009a91bcf8573d17339ae9e515172a72814fa8ae50fafaad240110aa574b1c3b210fe0bd8acfb5dc3a403c" },
    { 1, "11", "04d059caa369583e729c4ad0aaf35f32d01a5c240ab3d86452736544e77ff31be849efa31d3de2e6d93cd25fb6cb258423ce47a3ee05621e", "f5337a87f0418baa3d6fad1c4f9bc6e9031c82ccbc28df47d06442cdea4e5714d9681a19e05801653a308d500c79940ffa09f2432fd093c2" },
    { 1, "1f", "1a61d7fbb5175e98317f77eb7c7480bd51189ae1adcbf062a872586acaeb3ce1cffdd802a1a280bbd7fff6b115a7ea18d59456e924be8e51", "2b635c38377727c3a096e08cdce35959c9fe46d549df170fa39f1ea453df28f8f29c52d7e25ef0f1972e64b74b8ba3c2ed2ee04f091d62fc" },
    { 1, "20", "3959acf567fdf8ff8a332f2b868952699aaa105388cc60ac12237c84f514ca23c9c0a4357049dced3b12781bf37a549f8e709485eb287221", "050cac4a8a954fe93119a67275b8ea649430f6be7edeaedd0abae75d6f39be3c797c8b042cf0b9d68a03b0e2234932fb9ca1c122830e6694" },
    { 1, "21", "4fc2fd26999307f499854d39243bb0dcb330d6139fd6f1487545b5d93073054e455eefd4b6fdcfc8caf3a7a4e11675262b5cda12b8154c7a", "20ddb6b94b749e9fd9795cc8a470f2d4b7be136506e428031a36ef56b3aa9eb2842bc291697a8718d91d43ee7390d5714317109e3832b4fc" },
    { 1, "103", "e82419bf303edf4f9a8507ae1b03a5da1420623f18d474c62dbe55e17230044649b37e7db0180078548ad5ef82803fa54ee8bf5cb83d0915", "41527499bc4376c5a932bb523e8cb9f3121edf0e1df21a90f1c134e86ba20b8ff83840472c7b70b24480c3a530b766d9c017db950005c5d3" },
    { 1, "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2", "b094991bac714dc3aa95fb904db05d335ecd6d1587c872048db756bcf0a72094f52d1440414bb67f238eebad5586775eccbb3ea4e3e14774", "95644fa91fa5f7366b3aa03b0c1d16d027fb1a042b1fb41e1179d5c5b6143a9584f3e7fffdabf22e154ccbb750ed65a3020aff88b4557bcb" },
    { 1, "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" },
    { 1, "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f4", "4f6b66e4538eb23c556a046fb24fa2cca13292ea78378dfb7248a9420f58df6b0ad2ebbfbeb44980dc711452aa7988a13344c15b1c1eb88b", "95644fa91fa5f7366b3aa03b0c1d16d027fb1a042b1fb41e1179d5c5b6143a9584f3e7fffdabf22e154ccbb750ed65a3020aff88b4557bcb" },
    { 1, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffdf3288fa7113b6d26bb58da4085b309ca37163d548de30a4aad6113cc", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" },
    { 1, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffdf3288fa7113b6d26bb58da4085b309ca37163d548de30a4aad6113cd", "4f6b66e4538eb23c556a046fb24fa2cca13292ea78378dfb7248a9420f58df6b0ad2ebbfbeb44980dc711452aa7988a13344c15b1c1eb88b", "95644fa91fa5f7366b3aa03b0c1d16d027fb1a042b1fb41e1179d5c5b6143a9584f3e7fffdabf22e154ccbb750ed65a3020aff88b4557bcb" },
    { 1, "340d550056a420245ad29d36b71e08de500b9ac958e330b1821b4a5bf6c522caee1a36a6c7fc64c1315631d29ee1faf4d4f9ce4c1e09e2d4", "cfe0c95e16f885396c9f108462fc9032697db37d4d537ce98de28e13ac240ad22b10d05ef9a903df130de59aef7e72daedb62d19d989ffcc", "e1bbc230e347c25ff4cb4abf06e9270f2b91951cf0217f0130736ef82e4ce50c474776e890d3f2069df12b85b9a14868239374be74dfb15a" },
    { 1, "c59e8e6f582d396bce72a5dd68933b5c5b68f079f8766f193ce98fc98d521b0fdc5a58aa4e54fe18e75592ec783096eace0d9682f457da87", "ecd7e18592958b68db286f47fa70f053d7daafaf83e4b0fb50bf19d0a8addf3f1f85151d12d83ae53384a5d1fb9e51a5013da6d0b22307b4", "34c0ca371f9bf7317ff3ea264e421eb8f5b15ccf2b20bdeb64651094301fcf2269bb85fa3f3d6590e8c47d5e7f307149b4449fddc89b9da5" },
    { 1, "5a48fcd486018292e2c95480d0f97b1d31b7efad4bbbb7d1c80fbbf428da2d87c4bf6dd2099b6de4bfce39fecf885299dc1e526f63fd97eba5", "20d9212073c51b47919d58555bff53afd89f74b7e51e8581f87b184baf18d91a1e8514ec3a80d00bc947c9e048c325cdc38085441d97d42b", "683569bba49ad6a18f91166f982d0d850cdf563fdc6a46746d5bb1d8e3dee73deadd47d5eb2cb14adb8564c23fa15a8dd7f6068738c19a2b" },
    { 1, "46225e2619867e8fa57147eae1eedbbb888cc22d40a59a3606aa12e140d8239ac76f52b375223cfa7fe0c202307f0e83be074baf3b6639ef299a39cbfc8d019b21021930d8fda3fcd6918e", "4f258761e512f33d0f124da4f124cd3f3a925747441e1764672482caa866e0b158de263ce776d2b0eeab1e1ea41fa326a9549c03453f0d2e", "c806d37545169acffd06cf8a83de2140b646cae8b727682a97e7ddb8b7b392d3f3622598a6bedb4ab5eefc614c1fbb3d94f014929a8a0868" },
    { 2, "0", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" },
    { 2, "1", "95644fa91fa5f7366b3aa03b0c1d16d027fb1a042b1fb41e1179d5c5b6143a9584f3e7fffdabf22e154ccbb750ed65a3020aff88b4557bcb", "b094991bac714dc3aa95fb904db05d335ecd6d1587c872048db756bcf0a72094f52d1440414bb67f238eebad5586775eccbb3ea4e3e14774" },
    { 2, "2", "2da7da5ee9e2d9eadaf51fb145ff42518a22f0f2eca1303a422eba9b37a47789b2c0dd03c9219b3f37702602313917eb116b4755ac69a0cd", "88a3e4ecdeccdbfed2bc9f93b83e75df4fa3350cfd24df2c1a9482853b16f603e28f5f5131b58f4683b49e963b30aabfda3a5f7f452964e7" },
    { 2, "3", "6c488fc3fec8904912463c80c5c2ae7f9f609d162429c53ccc6c00ef7eb07423f74367f9665a7e3ed940974b849fdc15d4d71b3b5d302421", "5789a6c837456ddc016b54a3020cea12bbba5eb334373201e791c71f43f90e389c0aab78166095ce6c5f27876de7d6f99d402de82c0020c4" },
    { 2, "4", "e0b605b6915818a60751094058d941207298928129ac75ae2e7d6b24954618ecb00aa8851c116c941928f8a51d9ac268d45fd2d950943f48", "659fffd8c6fa6df84dc033c219a30e391b9808c2c2b0b5dd5039e50fb7545556feb404cefd3dfe9f66b8cdd98d5cb0933e6ec63e5fd3fcfd" },
    { 2, "10", "827109368a89385a087355ad6823918ed77d1fad5750792f81a8ce915c2bd283bf6e449a11e8f632f3f6c109c6d1eedcb59111f3849a80d5", "e4defac8d03d48c58d468cf530009a91bcf8573d17339ae9e515172a72814fa8ae50fafaad240110aa574b1c3b210fe0bd8acfb5dc3a403c" },
    { 2, "11", "f5337a87f0418baa3d6fad1c4f9bc6e9031c82ccbc28df47d06442cdea4e5714d9681a19e05801653a308d500c79940ffa09f2432fd093c2", "fb2fa6355c96a7c18d63b52f550ca0cd2fe5a3dbf54c279bad8c9aba18800ce417b6105ce2c21d1926c32da04934da7bdc31b85c11fa9de1" },
    { 2, "1f", "d49ca3c7c888d83c5f691f73231ca6a63601b92ab620e8f05c60e15aac20d7070d63ad281da10f0e68d19b48b4745c3d12d11fb0f6e29d03", "1a61d7fbb5175e98317f77eb7c7480bd51189ae1adcbf062a872586acaeb3ce1cffdd802a1a280bbd7fff6b115a7ea18d59456e924be8e51" },
    { 2, "20", "3959acf567fdf8ff8a332f2b868952699aaa105388cc60ac12237c84f514ca23c9c0a4357049dced3b12781bf37a549f8e709485eb287221", "050cac4a8a954fe93119a67275b8ea649430f6be7edeaedd0abae75d6f39be3c797c8b042cf0b9d68a03b0e2234932fb9ca1c122830e6694" },
    { 2, "21", "20ddb6b94b749e9fd9795cc8a470f2d4b7be136506e428031a36ef56b3aa9eb2842bc291697a8718d91d43ee7390d5714317109e3832b4fc", "b03d02d9666cf80b667ab2c6dbc44f234ccf29ec60290eb78aba4a25cf8cfab1baa1102b49023037350c585b1ee98ad9d4a325ed47eab385" },
    { 2, "103", "bead8b6643bc893a56cd44adc173460cede120f1e20de56f0e3ecb16945df47007c7bfb8d3848f4dbb7f3c5acf4899263fe8246afffa3a2c", "e82419bf303edf4f9a8507ae1b03a5da1420623f18d474c62dbe55e17230044649b37e7db0180078548ad5ef82803fa54ee8bf5cb83d0915" },
    { 2, "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2", "4f6b66e4538eb23c556a046fb24fa2cca13292ea78378dfb7248a9420f58df6b0ad2ebbfbeb44980dc711452aa7988a13344c15b1c1eb88b", "6a9bb056e05a08c994c55fc4f3e2e92fd804e5fbd4e04be1ee862a3949ebc56a7b0c180002540dd1eab33448af129a5cfdf500774baa8434" },
    { 2, "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffe", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },
    { 2, "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f4", "4f6b66e4538eb23c556a046fb24fa2cca13292ea78378dfb7248a9420f58df6b0ad2ebbfbeb44980dc711452aa7988a13344c15b1c1eb88b", "95644fa91fa5f7366b3aa03b0c1d16d027fb1a042b1fb41e1179d5c5b6143a9584f3e7fffdabf22e154ccbb750ed65a3020aff88b4557bcb" },
    { 2, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffdf3288fa7113b6d26bb58da4085b309ca37163d548de30a4aad6113cc", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" },
    { 2, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffdf3288fa7113b6d26bb58da4085b309ca37163d548de30a4aad6113cd", "95644fa91fa5f7366b3aa03b0c1d16d027fb1a042b1fb41e1179d5c5b6143a9584f3e7fffdabf22e154ccbb750ed65a3020aff88b4557bcb", "b094991bac714dc3aa95fb904db05d335ecd6d1587c872048db756bcf0a72094f52d1440414bb67f238eebad5586775eccbb3ea4e3e14774" },
    { 2, "340d550056a420245ad29d36b71e08de500b9ac958e330b1821b4a5bf6c522caee1a36a6c7fc64c1315631d29ee1faf4d4f9ce4c1e09e2d4", "cfe0c95e16f885396c9f108462fc9032697db37d4d537ce98de28e13ac240ad22b10d05ef9a903df130de59aef7e72daedb62d19d989ffcc", "e1bbc230e347c25ff4cb4abf06e9270f2b91951cf0217f0130736ef82e4ce50c474776e890d3f2069df12b85b9a14868239374be74dfb15a" },
    { 2, "c59e8e6f582d396bce72a5dd68933b5c5b68f079f8766f193ce98fc98d521b0fdc5a58aa4e54fe18e75592ec783096eace0d9682f457da87", "cb3f35c8e06408ce800c15d9b1bde1470a4ea330d4df42149b9aef6acfe030dd96447a05c0c29a6f173b82a180cf8eb64bbb60223764625a", "ecd7e18592958b68db286f47fa70f053d7daafaf83e4b0fb50bf19d0a8addf3f1f85151d12d83ae53384a5d1fb9e51a5013da6d0b22307b4" },
    { 2, "5a48fcd486018292e2c95480d0f97b1d31b7efad4bbbb7d1c80fbbf428da2d87c4bf6dd2099b6de4bfce39fecf885299dc1e526f63fd97eba5", "683569bba49ad6a18f91166f982d0d850cdf563fdc6a46746d5bb1d8e3dee73deadd47d5eb2cb14adb8564c23fa15a8dd7f6068738c19a2b", "df26dedf8c3ae4b86e62a7aaa400ac5027608b481ae17a7e0784e7b350e726e5e17aeb13c57f2ff436b8361fb73cda323c7f7abbe2682bd4" },
    { 2, "46225e2619867e8fa57147eae1eedbbb888cc22d40a59a3606aa12e140d8239ac76f52b375223cfa7fe0c202307f0e83be074baf3b6639ef299a39cbfc8d019b21021930d8fda3fcd6918e", "b0da789e1aed0cc2f0edb25b0edb32c0c56da8b8bbe1e89b98db7d3457991f4ea721d9c318892d4f1154e1e15be05cd956ab63fcbac0f2d1", "37f92c8abae9653002f930757c21debf49b9351748d897d568182246484c6d2c0c9dda67594124b54a11039eb3e044c26b0feb6d6575f797" },
};

#define NCASES (sizeof cases / sizeof cases[0])
#define LEN 56

static uint64_t rnd_state = 0x0123456789ABCDEFULL;

static uint64_t rnd(void)
{
    /* xorshift64 */
    rnd_state ^= rnd_state << 13;
    rnd_state ^= rnd_state >> 7;
    rnd_state ^= rnd_state << 17;
    return rnd_state;
}

/** Hex string to big-endian bytes, right-aligned in len bytes **/
static void from_hex(uint8_t *out, size_t len, const char *hex)
{
    size_t digits = strlen(hex), i;

    assert((digits + 1) / 2 <= len);
    memset(out, 0, len);
    for (i=0; i<digits; i++) {
        char ch = hex[digits - 1 - i];
        unsigned v = (ch >= '0' && ch <= '9') ? (unsigned)(ch - '0') : (unsigned)(ch - 'a' + 10);

        out[len - 1 - i/2] |= (uint8_t)(v << (4*(i % 2)));
    }
}

static PointEd448 *load_point(const Ed448Context *ctx, const char *x, const char *y)
{
    uint8_t xb[LEN], yb[LEN];
    PointEd448 *p;

    from_hex(xb, LEN, x);
    from_hex(yb, LEN, y);
    assert(ed448_new_point(&p, xb, yb, LEN, ctx) == 0);
    return p;
}

static void check_point(const PointEd448 *p, const char *x, const char *y)
{
    uint8_t xb[LEN], yb[LEN], xe[LEN], ye[LEN];

    from_hex(xe, LEN, x);
    from_hex(ye, LEN, y);
    assert(ed448_get_xy(xb, yb, LEN, p) == 0);
    assert(memcmp(xb, xe, LEN) == 0);
    assert(memcmp(yb, ye, LEN) == 0);
}

static void check_equal(const PointEd448 *a, const PointEd448 *b)
{
    uint8_t xa[LEN], ya[LEN], xb[LEN], yb[LEN];

    assert(ed448_get_xy(xa, ya, LEN, a) == 0);
    assert(ed448_get_xy(xb, yb, LEN, b) == 0);
    assert(memcmp(xa, xb, LEN) == 0);
    assert(memcmp(ya, yb, LEN) == 0);
    assert(ed448_cmp(a, b) == 0);
}

static const TestCase *find_case(int base, const char *k)
{
    size_t i;

    for (i=0; i<NCASES; i++)
        if (cases[i].base == base && strcmp(cases[i].k, k) == 0)
            return &cases[i];
    assert(0);
    return NULL;
}

static void test_context(void)
{
    Ed448Context *ctx;

    assert(ed448_new_context(NULL) == ERR_NULL);
    assert(ed448_new_context(&ctx) == 0);
    assert(ctx->k_words*64 >= 448 + EC_BLINDING_BITS);
    assert(ctx->windows*EC_WINDOW > 448 + EC_BLINDING_BITS);
    assert(nat_bit_length(ctx->group_order) == 448);
    ed448_free_context(ctx);
    ed448_free_context(NULL);
}

static void test_points(const Ed448Context *ctx)
{
    uint8_t x[LEN], y[LEN], big[LEN];
    PointEd448 *g, *pai, *t, *u, *v;
    const TestCase *g2 = find_case(0, "2"), *g3 = find_case(0, "3"), *gm = find_case(0, cases[11].k);

    from_hex(x, LEN, gx);
    from_hex(y, LEN, gy);

    /* Errors */
    assert(ed448_new_point(NULL, x, y, LEN, ctx) == ERR_NULL);
    assert(ed448_new_point(&t, x, y, 0, ctx) == ERR_NOT_ENOUGH_DATA);
    assert(ed448_new_point(&t, x, y, LEN + 1, ctx) == ERR_VALUE);
    y[LEN-1] ^= 1;
    assert(ed448_new_point(&t, x, y, LEN, ctx) == ERR_EC_POINT);
    assert(t == NULL);
    y[LEN-1] ^= 1;

    g = load_point(ctx, gx, gy);
    pai = load_point(ctx, "0", "1");
    check_point(g, gx, gy);
    check_point(pai, "0", "1");

    /* Shorter inputs, and coordinates not smaller than p (reduced) */
    assert(ed448_new_point(&t, (const uint8_t*)"\x00", (const uint8_t*)"\x01", 1, ctx) == 0);
    check_equal(t, pai);
    ed448_free_point(t);
    from_hex(big, LEN, p_plus_1);
    assert(ed448_new_point(&t, x, x, LEN, ctx) == ERR_EC_POINT);
    {
        uint8_t zero[LEN];

        memset(zero, 0, LEN);
        assert(ed448_new_point(&t, zero, big, LEN, ctx) == 0);   /* (0, p+1) = (0, 1) */
        check_equal(t, pai);
        ed448_free_point(t);
    }

    /* get_xy */
    assert(ed448_get_xy(x, y, LEN - 1, g) == ERR_NOT_ENOUGH_DATA);
    assert(ed448_get_xy(NULL, y, LEN, g) == ERR_NULL);

    /* cmp, clone, copy */
    assert(ed448_cmp(g, g) == 0);
    assert(ed448_cmp(g, pai) == ERR_VALUE);
    assert(ed448_clone(&t, g) == 0);
    check_equal(t, g);
    assert(ed448_copy(t, pai) == 0);
    check_equal(t, pai);

    /* 2G = G + G (with different Z), 3G = 2G + G = G + 2G */
    assert(ed448_copy(t, g) == 0);
    assert(ed448_double(t) == 0);
    check_point(t, g2->rx, g2->ry);
    assert(ed448_clone(&u, g) == 0);
    assert(ed448_add(u, g) == 0);
    check_equal(t, u);
    assert(ed448_add(t, g) == 0);
    check_point(t, g3->rx, g3->ry);
    assert(ed448_clone(&v, g) == 0);
    assert(ed448_add(v, u) == 0);
    check_equal(t, v);

    /* a + a (the same object) */
    assert(ed448_copy(t, g) == 0);
    assert(ed448_add(t, t) == 0);
    check_point(t, g2->rx, g2->ry);

    /* -G = (n-1)G; G + (-G) = 0; 0 + G = G; 2*0 = 0 */
    assert(ed448_copy(u, g) == 0);
    assert(ed448_neg(u) == 0);
    check_point(u, gm->rx, gm->ry);
    assert(ed448_copy(t, g) == 0);
    assert(ed448_add(t, u) == 0);
    check_equal(t, pai);
    assert(ed448_add(t, g) == 0);
    check_equal(t, g);
    assert(ed448_copy(t, pai) == 0);
    assert(ed448_double(t) == 0);
    check_equal(t, pai);

    assert(ed448_add(NULL, g) == ERR_NULL);
    assert(ed448_double(NULL) == ERR_NULL);
    assert(ed448_neg(NULL) == ERR_NULL);
    assert(ed448_cmp(NULL, g) == ERR_NULL);

    ed448_free_point(g);
    ed448_free_point(pai);
    ed448_free_point(t);
    ed448_free_point(u);
    ed448_free_point(v);
    ed448_free_point(NULL);
}

static void test_on_curve(const Ed448Context *ctx)
{
    PointEd448 *g;
    EcWs ws;

    assert(ec_ws_new(&ws, ctx->field) == 0);
    g = load_point(ctx, gx, gy);
    assert(ed448_on_curve(&ws, ctx, g->x, g->y, g->z) == 1);
    assert(ed448_double(g) == 0);               /* Z != 1 */
    assert(ed448_on_curve(&ws, ctx, g->x, g->y, g->z) == 1);
    g->y[0] ^= 1;
    assert(ed448_on_curve(&ws, ctx, g->x, g->y, g->z) == 0);
    memset(g->x, 0, 3*ED448_WORDS*8);            /* (0:0:0) */
    assert(ed448_on_curve(&ws, ctx, g->x, g->y, g->z) == 0);
    ed448_free_point(g);
    ec_ws_free(&ws);
}

static void test_scalar(const Ed448Context *ctx)
{
    uint8_t k[100];
    size_t i;
    unsigned s;

    for (i=0; i<NCASES; i++) {
        const TestCase *tv = &cases[i];
        size_t len = (strlen(tv->k) + 1) / 2;

        if (len == 0)
            len = 1;
        from_hex(k, len, tv->k);
        /* With different seeds, and with leading zeros */
        for (s=0; s<3; s++) {
            PointEd448 *p;
            size_t pad = s == 2 ? 9 : 0;
            uint8_t kp[110];

            if (tv->base == 0)
                p = load_point(ctx, gx, gy);
            else if (tv->base == 1)
                p = load_point(ctx, qx, qy);
            else
                p = load_point(ctx, qtx, qty);
            memset(kp, 0, pad);
            memcpy(kp + pad, k, len);
            assert(ed448_scalar(p, kp, len + pad, rnd()) == 0);
            check_point(p, tv->rx, tv->ry);
            ed448_free_point(p);
        }
    }

    {
        PointEd448 *p = load_point(ctx, gx, gy);

        assert(ed448_scalar(NULL, k, 1, 0) == ERR_NULL);
        assert(ed448_scalar(p, NULL, 1, 0) == ERR_NULL);
        assert(ed448_scalar(p, k, 0, 0) == ERR_NOT_ENOUGH_DATA);
        ed448_free_point(p);
    }
}

/* The tables: entry j of window i is (j+1)*32^i*G (checked with the variable base code) */
static void test_g_table(const Ed448Context *ctx)
{
    uint8_t k[100];
    unsigned n;

    for (n=0; n<40; n++) {
        PointEd448 *p, *q, *m;
        size_t i, j, bit;

        i = n < 2 ? n*(ctx->windows - 1) : rnd() % ctx->windows;
        j = n < 2 ? 15 : rnd() % EC_DIGITS;

        /* (j+1) << (5*i) */
        memset(k, 0, sizeof k);
        bit = 5*i;
        k[sizeof k - 1 - bit/8] = (uint8_t)((j + 1) << (bit % 8));
        k[sizeof k - 2 - bit/8] = (uint8_t)((j + 1) >> (8 - bit % 8));

        /* A point equal to G, but not detected as G (Z != 1) */
        p = load_point(ctx, gx, gy);
        assert(ed448_double(p) == 0);
        m = load_point(ctx, gx, gy);
        assert(ed448_neg(m) == 0);
        assert(ed448_add(p, m) == 0);
        assert(ed448_scalar(p, k, sizeof k, rnd()) == 0);
        ed448_free_point(m);

        q = load_point(ctx, "0", "1");
        memcpy(q->x, ctx->g_table + (i*EC_DIGITS + j)*2*ED448_WORDS, ED448_WORDS*8);
        memcpy(q->y, ctx->g_table + (i*EC_DIGITS + j)*2*ED448_WORDS + ED448_WORDS, ED448_WORDS*8);
        assert(ed448_cmp(p, q) == 0);

        /* The same with G itself (fixed base) */
        ed448_free_point(p);
        p = load_point(ctx, gx, gy);
        assert(ed448_scalar(p, k, sizeof k, rnd()) == 0);
        assert(ed448_cmp(p, q) == 0);

        ed448_free_point(p);
        ed448_free_point(q);
    }
}

/* k1*(k2*P) = k2*(k1*P), and (k1 + k2)*P = k1*P + k2*P, for random scalars */
static void test_random(const Ed448Context *ctx)
{
    uint8_t k1[LEN], k2[LEN], ks[LEN + 1];
    unsigned t;
    size_t i;

    for (t=0; t<10; t++) {
        PointEd448 *a, *b, *s;
        int carry = 0;
        const char *bx = t % 2 ? qtx : gx, *by = t % 2 ? qty : gy;

        for (i=0; i<LEN; i++) {
            k1[i] = (uint8_t)rnd();
            k2[i] = (uint8_t)rnd();
        }
        a = load_point(ctx, bx, by);
        b = load_point(ctx, bx, by);
        assert(ed448_scalar(a, k2, LEN, rnd()) == 0);
        assert(ed448_scalar(a, k1, LEN, rnd()) == 0);
        assert(ed448_scalar(b, k1, LEN, rnd()) == 0);
        assert(ed448_scalar(b, k2, LEN, rnd()) == 0);
        check_equal(a, b);
        ed448_free_point(a);
        ed448_free_point(b);

        for (i=LEN; i-- > 0;) {
            int v = k1[i] + k2[i] + carry;

            ks[i + 1] = (uint8_t)v;
            carry = v >> 8;
        }
        ks[0] = (uint8_t)carry;
        a = load_point(ctx, bx, by);
        b = load_point(ctx, bx, by);
        s = load_point(ctx, bx, by);
        assert(ed448_scalar(a, k1, LEN, rnd()) == 0);
        assert(ed448_scalar(b, k2, LEN, rnd()) == 0);
        assert(ed448_add(a, b) == 0);
        assert(ed448_scalar(s, ks, LEN + 1, rnd()) == 0);
        check_equal(a, s);
        ed448_free_point(a);
        ed448_free_point(b);
        ed448_free_point(s);
    }
}

static void test_other_context(const Ed448Context *ctx)
{
    Ed448Context *ctx2;
    PointEd448 *a, *b;

    assert(ed448_new_context(&ctx2) == 0);
    a = load_point(ctx, "0", "1");
    b = load_point(ctx2, "0", "1");
    assert(ed448_add(a, b) == ERR_EC_CURVE);
    assert(ed448_cmp(a, b) == ERR_EC_CURVE);
    ed448_free_point(a);
    /* A point can be freed after its context */
    ed448_free_context(ctx2);
    ed448_free_point(b);
}

int main(void)
{
    Ed448Context *ctx;

#if defined(TEST_BMI2_ADX)
    if (!have_bmi2_adx()) {
        if (getenv("NAT_REQUIRE_BMI2_ADX")) {
            printf("BMI2 and ADX are required but not available\n");
            return 1;
        }
        printf("Skipping: the CPU does not support BMI2 and ADX\n");
        return 0;
    }
#endif

    test_context();
    assert(ed448_new_context(&ctx) == 0);
    test_points(ctx);
    test_on_curve(ctx);
    test_scalar(ctx);
    test_g_table(ctx);
    test_random(ctx);
    test_other_context(ctx);
    ed448_free_context(ctx);
    return 0;
}

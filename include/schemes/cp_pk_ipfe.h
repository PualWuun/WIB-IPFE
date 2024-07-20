#include "pbc/pbc.h"
#include "ibe/MasterKey.h"
#include "ibe/PublicKey.h"
#include "ibe/SecretKey.h"
#include "ibe/CipherText.h"
#include "ibe/HIDparam.h"
#include "utils/func.h"
#include "curve/params.h"
#include <unordered_map>
#include <string>

class CP_PK_IPFE {
    private:
    MasterKeyCP *MSK;
    bool init = false;
    pairing_t pairing;
    std::unordered_map<std::string, element_t *> Dlog_table;
    element_t gs_base, gs_step;
    int Dlog_table_len, gslen;

    element_t *myDlog(element_t &target);

    element_t *myDlog_rho(element_t &base, element_t &target, element_t &Zr);

    public:
    int n, d, decrypt_max;
    PublicKeyCP *PK = NULL;

    ElementList *I2Zp(std::vector<int> p, bool zero_padding);

    ElementList *GenZnList(int len);

    void change_type(std::string &param);

    void cleanSetUp();

    PublicKeyCP *SetUp(int n, pairing_t &pairing, MasterKeyCP *MSK);

    CiphertextCP *Encrypt(PublicKeyCP *PK, ElementList *a_c, ElementList *y, std::string policy);

    SecretKeyCP *KetGen(MasterKeyCP *MSK, ElementList *x, ElementList *a_k, std::vector<std::string> *attributes);

    element_s* decryptNode(CiphertextCP *CT, SecretKeyCP *SK, multiway_tree_node *x);

    element_t *Decrypt(CiphertextCP *CT, SecretKeyCP *SK, PublicKeyCP *PK);

    void init_dlog(int table_len);

    void init_max_res(int res);

    ~CP_PK_IPFE();
};
#include "schemes/ibbe_pk_ipfe.h"

element_t *IBBE_PK_IPFE::myDlog_rho(element_t &base, element_t &target, element_t &Zr) {
    static element_t res;
    element_init_same_as(res, Zr);
    element_dlog_pollard_rho(res, base, target);
    return &res;
};

element_t *IBBE_PK_IPFE::myDlog(element_t &target) {
    if(this->Dlog_table_len == 0) this->init_dlog(100);
    if(this->gslen == 0) this->init_max_res(10000);
    
    element_t *res = (element_t *)(new element_t);
    element_init_same_as(*res, this->gs_step);
    element_set0(*res);
    int buflen = 1024;
    char buf[buflen];
    std::string key;
    for(int i = 0;i < this->gslen;i++) {
        element_snprint(buf, buflen, target);
        key = buf;
        key = H1(key);
        if(this->Dlog_table.find(key) != this->Dlog_table.end()) {
            element_add(*res, *res, *this->Dlog_table[key]);
            return res;
        }
        element_div(target, target, this->gs_base);
        element_add(*res, *res, this->gs_step);
    }
    element_clear(*res);
    return NULL;
};

ElementList *IBBE_PK_IPFE::I2Zp(std::vector<int> p, bool zero_padding) {
    int len = std::min(this->PK->GetH_r_1_alpha()->len(), (int)p.size());
    int ele_len = len;
    if(zero_padding) ele_len = this->PK->GetH_r_1_alpha()->len();
    ElementList *res = new ElementList(ele_len, 0, *this->MSK->GetAlpha(), false);
    for(int i = 0;i < len;i++) element_set_si(*res->At(i + 1), p[i]);
    return res;
}

ElementList *IBBE_PK_IPFE::GenZnList(int len) {
    return new ElementList(len, 0, *this->MSK->GetAlpha(), true);
};

void IBBE_PK_IPFE::change_type(std::string &param) {
    pbc_param_t par;
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(this->pairing, par);
    this->init_dlog(0);
    pbc_param_clear(par);
};

void IBBE_PK_IPFE::cleanSetUp() {
    if(this->PK != NULL) delete this->PK;
    this->PK = NULL;
}

PublicKeyIBBE *IBBE_PK_IPFE::SetUp(int n){
    this->MSK = new MasterKeyIBBE(n, this->pairing);
    this->PK = new PublicKeyIBBE(n, this->pairing, this->MSK);
    this->n = n;
    this->decrypt_max = decrypt_max;
    this->init = true;
    return this->PK;
};

CiphertextIBBE *IBBE_PK_IPFE::Encrypt(PublicKeyIBBE *PK, ElementList *S, ElementList *x){
    return new CiphertextIBBE(PK, S, x);
};

SecretKeyIBBE *IBBE_PK_IPFE::KeyGen(PublicKeyIBBE *PK, MasterKeyIBBE *MSK, element_t &ID, ElementList *y){
    return new SecretKeyIBBE(this->PK, this->MSK, ID, y);
};

element_t *IBBE_PK_IPFE::Decrypt(CiphertextIBBE *CT, ElementList *S, SecretKeyIBBE *SK, PublicKeyIBBE *PK){
    int i;
    for(i = 1; i <= S->len(); i++){
        if(!element_cmp(*S->At(i), *SK->GetID())){
            break;
        }
    }
    
    ElementList *S_remove_i = new ElementList(S,0);
    S_remove_i->remove_front_at(i);

    //TODO: Compute the polynomials (a-ID_1)....(a-ID_s) = a^s + (-1)^{s-1} * C(s,s-1) * a^{s-1} * (ID_1+..ID_s)
    ElementList *ployA = new ElementList(S_remove_i->len() + 1 , 0, *S_remove_i->At(1), false);
    ElementList *ployB = new ElementList(S_remove_i->len() + 1, 0, *S_remove_i->At(1), false);
    for(int i = 1; i <= S_remove_i->len() + 1; i++){
        element_init_same_as(*ployA->At(i), *SK->GetID());
        element_set0(*ployA->At(i));
        element_init_same_as(*ployB->At(i),*SK->GetID());
        element_set0(*ployB->At(i));
    }
    element_set(*ployA->At(1), *S->At(1));
    element_set1(*ployA->At(1));
    for(int i = 2; i <= S_remove_i->len() + 1; i++){
        element_set1(*ployA->At(i+1));
        for(int j = i; j >= 2; j--){
            element_mul(*ployB->At(j), *ployA->At(j), *S->At(i));
            element_mul(*ployA->At(j), *ployA->At(j-1), *ployB->At(j));
        }
        element_mul(*ployA->At(1), *ployA->At(1),*S->At(i));
    }
    element_set0(*ployA->At(1));
    element_t temp1, temp2;
    element_init_same_as(temp1, *PK->GetG());
    element_init_same_as(temp2, *PK->GetG());
    element_set1(temp1);
    for(int i = 0; i < S_remove_i->len() + 1; i++){
        element_pow_zn(temp2, *PK->GetH_r_1_alpha_i(i), *ployA->At(i+2));
        element_mul(temp1, temp1, temp2);
    }
    //temp1 = h^{p_{j,S}(\alpha)}

    element_t A, B, D, res1;
    element_init_same_as(A, *PK->GetEgh());
    element_init_same_as(B, *PK->GetEgh());
    element_init_same_as(D, *PK->GetEgh());
    element_init_same_as(res1, *PK->GetEgh());
    element_set1(res1);
    for(int i = 1; i <= this->n ; i++){
        element_pow_zn(temp2,*CT->GetC_i_1_i(i), *SK->GetY()->At(i));
        element_mul(res1, res1, temp2);
    }
    element_pairing(A, res1, temp1);

     //res1 = e( K_{1,ID_{j,y_j}} , C_0)
    element_pairing(res1, *SK->GetK_1(), *CT->GetC_0());
    element_mul(A, A, res1);

    //
    element_t temp3, temp4;
    element_init_same_as(temp3, *PK->GetG());
    element_invert(temp3, *CT->GetC_2());
    element_pow_zn(temp3, temp3, *SK->GetK_2());
    element_pairing(B, temp3, temp1);   // B = e(C_2^{K_2}, h^{p_{j,S}(\alpha)})

    element_init_same_as(temp4, *SK->GetK_2());
    element_set1(temp4);
    
    //ReSet res1 = C_1^{(-1)^s }
    for(int i = 1; i <= S_remove_i->len(); i++){
        element_mul(temp4, temp4, *S_remove_i->At(i));
    }
    element_mul(temp4, temp4, *SK->GetK_2());
    if((S->len()+1)%2 == 0){
        element_mul(B, B, temp4);
    }
    else{
        element_div(B, B , temp4);
    }

    element_mul(D, A, B);
    element_div(temp4, temp4, *SK->GetK_2());   //ReSet temp4 = \prod ID_i, i\ne j
    element_invert(temp4, temp4);
    if((S->len()+1)%2 == 0){
        element_pow_zn(D, D, temp4);
    }
    else{
        element_neg(temp4, temp4);
        element_pow_zn(D, D , temp4);
    }

    element_t eggres, res2;
    element_init_same_as(eggres, *PK->GetEgh());
    element_set1(eggres);
    element_set1(res2);
    for(int i = 1; i < this->n; i++){
        element_pow_zn(res2, res2, *SK->GetY()->At(i));
        element_mul(eggres, eggres, res2);
    }
    element_div(eggres, eggres, D);

    element_t *res = this->myDlog(eggres);

    element_clear(eggres);
    element_clear(res2);
    element_clear(res1);
    element_clear(temp4);
    element_clear(temp3);
    element_clear(temp2);
    element_clear(temp1);
    element_clear(D);
    element_clear(B);
    element_clear(A);

    if(ployA != NULL) delete ployA;
    if(ployB != NULL) delete ployB;
    return res;
};

void IBBE_PK_IPFE::init_dlog(int table_len) {
    this->gslen = 0;
    for(auto kv: this->Dlog_table) element_clear(*kv.second);
    this->Dlog_table.clear();
    this->Dlog_table_len = table_len;
    if(table_len == 0) return;
    element_t base, res, index, adder;
    element_init_same_as(base, *this->PK->GetEgh());
    element_init_same_as(res, *this->PK->GetEgh());
    element_init_same_as(index, *this->MSK->GetAlpha());
    element_init_same_as(adder, *this->MSK->GetAlpha());
    element_set(base, *this->PK->GetEgh());
    element_set0(index);
    element_set1(adder);
    std::string key;
    int buflen = 1024;
    char buf[buflen];
    for(int i = 0;i < this->Dlog_table_len;i++) {
        element_pow_zn(res, base, index);
        element_snprint(buf, buflen, res);
        key = buf;
        key = H1(key);
        this->Dlog_table.insert(std::make_pair(key, (element_t *)(new element_t)));
        element_init_same_as(*this->Dlog_table[key], index);
        element_set(*this->Dlog_table[key], index);
        element_add(index, index, adder);
    }
    element_init_same_as(this->gs_base, *this->PK->GetEgh());
    element_pow_zn(this->gs_base, *this->PK->GetEgh(), index);
    element_init_same_as(this->gs_step, index);
    element_set(this->gs_step, index);

    element_clear(base);
    element_clear(res);
    element_clear(index);
    element_clear(adder);
};

void IBBE_PK_IPFE::init_max_res(int res) {
    if(this->Dlog_table_len == 0) return;
    this->gslen = (res / this->Dlog_table_len) + 1;
};

IBBE_PK_IPFE::~IBBE_PK_IPFE() {
    if(this->MSK != NULL) delete this->MSK;
    if(this->PK != NULL) delete this->PK;
    for(auto kv: this->Dlog_table) delete kv.second;
    pairing_clear(this->pairing);
}
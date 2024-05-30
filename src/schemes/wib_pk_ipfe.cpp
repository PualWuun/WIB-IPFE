#include <omp.h>
#include "schemes/wib_pk_ipfe.h"
#include "utils/func.h"

element_t *WIB_PK_IPFE::myDlog_rho(element_t &base, element_t &target, element_t &Zr){
    static element_t res;
    element_init_same_as(res, Zr);
    element_dlog_pollard_rho(res, base, target);
    return &res;
};

element_t *WIB_PK_IPFE::myDlog(element_t &target){
    if(this->Dlog_table_len == 0) this->init_dlog(100);
    if(this->gslen == 0) this->init_max_res(10000);

    element_t *res = (element_t *) (new element_t);
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

WIB_PK_IPFE::WIB_PK_IPFE(){
    CurveParams curves;
    this->change_type(curves.a_param);
};

void WIB_PK_IPFE::change_type(std::string &param){
    pbc_param_t par;
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(this->pairing, par);  
    this->init_dlog(0);
    pbc_param_clear(par);
};

ElementList *WIB_PK_IPFE::I2Zp(std::vector<int> p, bool zero_padding){
    int len = std::min(this->MSK->GetZ()->len(), (int) p.size());
    int ele_len = len;
    if(zero_padding) ele_len = this->MSK->GetZ()->len();
    ElementList *res = new ElementList(ele_len, 0 ,*this->MSK->GetAlpha(), false);
    for(int i = 0; i < len; i++){
        element_set_si(*res->At(i+1), p[i]);
    }
    return res;
};

ElementList *WIB_PK_IPFE::GenZnList(int len){
    return new ElementList(len, 0, *this->MSK->GetAlpha(), true);
};

void WIB_PK_IPFE::cleanSetUp(){
    if(this->MSK != NULL) delete this->MSK;
    if(this->PK != NULL) delete this->PK;
    if(this->E_G_H_1_Z_i != NULL) delete this->E_G_H_1_Z_i;
    this->MSK = NULL;
    this->PK = NULL;
    this->E_G_H_1_Z_i = NULL;
};

PublicKeyWIB *WIB_PK_IPFE::Setup(int n, int d){
    this->cleanSetUp();
    this->MSK = new MasterKeyWIB(n, this->pairing);
    this->PK = new PublicKeyWIB(n, d, this->pairing, this->MSK);
    this->E_G_H_1_Z_i = NULL;
    return this->PK;
};

SecretKeyWIB *WIB_PK_IPFE::KeyGen(ElementList *P, ElementList *y, HIDparamWIB *param){
    return this->KeyGen(this->PK, P, y,param);
};

SecretKeyWIB *WIB_PK_IPFE::KeyGen(PublicKeyWIB *PK, ElementList *P, ElementList *y, HIDparamWIB *param){
    return new SecretKeyWIB(PK, this->MSK, P, y, param);
};

CipherTextWIB *WIB_PK_IPFE::Encrypt(ElementList *P, ElementList *x, HIDparamWIB *param){
    return this->Encrypt(this->PK, P, x, param);
};

CipherTextWIB *WIB_PK_IPFE::Encrypt(PublicKeyWIB *PK, ElementList *P, ElementList *x, HIDparamWIB *param){
    if(this->E_G_H_1_Z_i == NULL) {
        int n = this->MSK->GetZ()->len();
        this->E_G_H_1_Z_i = new ElementList(n, 0, *this->PK->GetEgg(), false);
        for(int i = 1;i <= n;i++) element_pairing(*this->E_G_H_1_Z_i->At(i), *this->PK->GetG(), *this->PK->GetH_1_Z_i(i));
    }
    return new CipherTextWIB(PK, P, x, this->E_G_H_1_Z_i, param);
};

element_t *WIB_PK_IPFE::Decrypt(CipherTextWIB *CT, SecretKeyWIB *SK){
    return this->Decrypt(this->PK, CT, SK);
};

element_t *WIB_PK_IPFE::Decrypt(PublicKeyWIB *PK, CipherTextWIB *CT, SecretKeyWIB *SK){
    int n = CT->GetC_x()->len(), d = CT->GetP()->len();
    element_t eggres, tmp, tmp1, tmp2, a_tmp;
    element_init_same_as(eggres, *PK->GetEgg());
    element_init_same_as(tmp, *PK->GetEgg());
    element_init_same_as(tmp1, *CT->GetC_1());
    element_init_same_as(tmp2, *PK->GetEgg());
    element_init_same_as(a_tmp, *PK->GetG());
    element_set(a_tmp, *SK->GetA_i(1));     //a_tmp = a_1

    //a_tmp
    for(int i = 1; i <= d; i++){
        if(!element_is0(*CT->GetP()->At(i))){   
            if(element_is0(*SK->GetP_i(i))){
                element_pow_zn(tmp1, *SK->GetB_i(i),*CT->GetP()->At(i));
                element_mul(a_tmp, a_tmp, tmp1);
            }
        }
        else{
            if(element_is0(*SK->GetP_i(i))){
                element_mul(a_tmp, a_tmp, *SK->GetC_i(i));
            }
            else{
                element_mul(a_tmp, a_tmp, *SK->GetD_i(i));
            }
        }
    }
    
    //C_2 = e(g,g)^{sr_1<z,y>}
    element_pow_zn(tmp, *CT->GetC_2(), *SK->GetR_1_zy());

    //e((g,g)^{<x,y>})
    for(int i = 1; i <=n; i++){
        element_pow_zn(tmp2, *CT->GetC_x_i(i), *SK->GetY_i(i));
        element_mul(eggres, eggres, tmp2);
    }

    element_pairing(tmp2, *CT->GetC_1(), a_tmp);
    element_mul(eggres, eggres, tmp2);

    //e(a_2,C_3)
    element_pairing(tmp2, *SK->GetA_i(2), *CT->GetC_3());
    element_div(eggres, eggres, tmp2);

    //e(a_3, C_4)
    element_pairing(tmp2, *SK->GetA_i(3), *CT->GetC_4());
    element_div(eggres, eggres, tmp2);

    element_mul(eggres, eggres, tmp);

    // return this->myDlog_rho(*PK->GetEgg(), eggres, *SK->GetY_i(1));
    element_t *res = this->myDlog(eggres);

    element_clear(eggres);
    element_clear(tmp);
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(a_tmp);
    return res;
};

SecretKeyWIB *WIB_PK_IPFE::Delegate(SecretKeyWIB *SK, ElementList *P_new, HIDparamWIB *param){
    return this->Delegate(this->PK, SK, P_new, param);
};

SecretKeyWIB *WIB_PK_IPFE::Delegate(PublicKeyWIB *PK, SecretKeyWIB *SK, ElementList *P_new, HIDparamWIB *param){
    return new SecretKeyWIB(PK, SK, P_new ,param);
};

void WIB_PK_IPFE::init_dlog(int table_len){
    this->gslen = 0;
    for(auto kv: this->Dlog_table) element_clear(*kv.second);
    this->Dlog_table.clear();
    this->Dlog_table_len = table_len;
    if(table_len == 0) return;
    element_t base, res, index, adder;
    element_init_same_as(base, *this->PK->GetEgg());
    element_init_same_as(res, *this->PK->GetEgg());
    element_init_same_as(index, *this->MSK->GetAlpha());
    element_init_same_as(adder, *this->MSK->GetAlpha());
    element_set(base, *this->PK->GetEgg());
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
    element_init_same_as(this->gs_base, *this->PK->GetEgg());
    element_pow_zn(this->gs_base, *this->PK->GetEgg(), index);
    element_init_same_as(this->gs_step, index);
    element_set(this->gs_step, index);

    element_clear(base);
    element_clear(res);
    element_clear(index);
    element_clear(adder);
};

void WIB_PK_IPFE::init_max_res(int res){
    if(this->Dlog_table_len == 0) return;
    this->gslen = (res / this->Dlog_table_len) + 1;
};

std::string WIB_PK_IPFE::toString(){
    std::string res = "WIB_IPFE_CPA类\n";
    if(this->MSK != NULL) res += this->MSK->toString() + "\n";
    if(this->PK != NULL) res += this->PK->toString() + "\n";
    return res;
};

WIB_PK_IPFE::~WIB_PK_IPFE(){
    if(this->MSK != NULL) delete this->MSK;
    if(this->PK != NULL) delete this->PK;
    for(auto kv: this->Dlog_table) delete kv.second;
    if(this->E_G_H_1_Z_i != NULL) delete this->E_G_H_1_Z_i;
    element_clear(this->gs_base);
    element_clear(this->gs_step);
    pairing_clear(this->pairing);
    this->MSK = NULL;
    this->PK =NULL;
    this->E_G_H_1_Z_i = NULL;
};
#include "schemes/cp_pk_ipfe.h"

element_t *CP_PK_IPFE::myDlog_rho(element_t &base, element_t &target, element_t &Zr) {
    static element_t res;
    element_init_same_as(res, Zr);
    element_dlog_pollard_rho(res, base, target);
    return &res;
};

element_t *CP_PK_IPFE::myDlog(element_t &target) {
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

ElementList *CP_PK_IPFE::I2Zp(std::vector<int> p, bool zero_padding) {
    int len = p.size();
    int ele_len = len;
    if(zero_padding) ele_len = this->PK->GetE_g1_g2_sk_F_i(0)->len();
    ElementList *res = new ElementList(ele_len, 0, *this->MSK->GetS_k(), false);
    for(int i = 0;i < len;i++) element_set_si(*res->At(i + 1), p[i]);
    return res;
}

ElementList *CP_PK_IPFE::GenZnList(int len) {
    return new ElementList(len, 0, *this->MSK->GetS_k(), true);
};

void CP_PK_IPFE::change_type(std::string &param) {
    pbc_param_t par;
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(this->pairing, par);
    this->init_dlog(0);
    pbc_param_clear(par);
};

void CP_PK_IPFE::cleanSetUp() {
    if(this->PK != NULL) delete this->PK;
    this->PK = NULL;
}


PublicKeyCP *CP_PK_IPFE::SetUp(int n, pairing_t &pairing, MasterKeyCP *MSK){
    this->cleanSetUp();
    this->MSK = new MasterKeyCP(n, pairing);
    this->PK = new PublicKeyCP(n, pairing, MSK);
    return this->PK;
};

CiphertextCP *CP_PK_IPFE::Encrypt(PublicKeyCP *PK, ElementList *a_c, ElementList *y, std::string policy){
    return new CiphertextCP(PK, a_c, y, policy);
};

SecretKeyCP *CP_PK_IPFE::KetGen(MasterKeyCP *MSK, ElementList *x, ElementList *a_k, std::vector<std::string> *attributes){
    return new SecretKeyCP(MSK, x, a_k, attributes);
};

element_s* CP_PK_IPFE::decryptNode(CiphertextCP *CT, SecretKeyCP *SK, multiway_tree_node *x){
    signed long int child_index = 1;
    multiway_tree_node *child_node = x->getFirstChild();
    map<signed long int, element_s*> available_Fzs;
    while (child_node != NULL) {
        element_s *Fz = decryptNode(CT, SK, child_node);
        if (Fz != NULL) {
            element_t *insert_Fz = new element_t[1];
            element_init_same_as(*insert_Fz, Fz);
            element_set(*insert_Fz, Fz);
            available_Fzs.insert(pair<signed long int, element_s*>(child_index, *insert_Fz));
        }
        ++child_index;
        child_node = child_node->getNextSibling();
    }

    if (available_Fzs.size() < x->getThreshold()) {
        return NULL;
    }

    element_t *result = new element_t[1];
    element_init_GT(*result, pairing);
    map<signed long int, element_s*>::iterator iterator1;
    for (iterator1 = available_Fzs.begin(); iterator1 != available_Fzs.end(); ++iterator1) {
        element_t i;
        element_init_Zr(i, pairing);
        element_set_si(i, iterator1->first);

        // compute lagrange_coefficient
        element_t lagrange_coefficient;
        element_init_Zr(lagrange_coefficient, pairing);
        element_set1(lagrange_coefficient);
        map<signed long int, element_s*>::iterator iterator2;
        for (iterator2 = available_Fzs.begin(); iterator2 != available_Fzs.end(); ++iterator2) {
            if (iterator2->first == iterator1->first) {
                continue;
            }
            element_t j;
            element_init_Zr(j, pairing);
            element_set_si(j, iterator2->first);
            element_t j_i;
            element_init_Zr(j_i, pairing);
            element_sub(j_i, j, i);
            element_t item;
            element_init_Zr(item, pairing);
            element_div(item, j, j_i);
            element_mul(lagrange_coefficient, lagrange_coefficient, item);
        }

        // compute Fz_delta
        element_t Fz_delta;
        element_init_GT(Fz_delta, pairing);
        element_pow_zn(Fz_delta, iterator1->second, lagrange_coefficient);

        if (iterator1 == available_Fzs.begin()) {
            element_set(*result, Fz_delta);
        } else {
            element_mul(*result, *result, Fz_delta);
        }
    }
    return *result;
};

element_t *CP_PK_IPFE::Decrypt(CiphertextCP *CT, SecretKeyCP *SK, PublicKeyCP *PK){
    ElementList *e_sk2_c2 = new ElementList(CT->GetC_1()->size(), 0, *PK->GetE_g1_g2(), false);
    ElementList *e_sk3_c3 = new ElementList(CT->GetC_1()->size(), 0, *PK->GetE_g1_g2(), false);
    for(int i = 0; i < (int) CT->GetC_1()->size(); i++){
        element_pairing(*e_sk2_c2->At(i+1),*SK->GetSK_2_i(i), *CT->GetC_1_i(i));
        element_pairing(*e_sk3_c3->At(i+1),*SK->GetSK_3_i(i), *CT->GetC_3_i(i));
        element_div(*e_sk2_c2->At(i+1), *e_sk2_c2->At(i+1), *e_sk3_c3->At(i+1));
    }

    ElementList *e_sk1_c4 = new ElementList(CT->GetC_1()->size(), 0, *PK->GetE_g1_g2(), false);
    ElementList *e_sk4_c5 = new ElementList(CT->GetC_1()->size(), 0, *PK->GetE_g1_g2(), false);
    for(int i = 0; i < (int) CT->GetC_5()->size(); i++){
        element_pairing(*e_sk1_c4->At(i+1),*SK->GetSK_1_i(i), *CT->GetC_4());
        element_pairing(*e_sk4_c5->At(i+1),*SK->GetSK_3_i(i), *CT->GetC_5_i(i));
        element_div(*e_sk1_c4->At(i+1), *e_sk1_c4->At(i+1), *e_sk4_c5->At(i+1));
    }

    element_t res1, res2;
    element_init_same_as(res1, *PK->GetE_g1_g2());
    element_set1(res1);
    element_init_same_as(res2, *PK->GetE_g1_g2());
    for(int i = 0; i < (int) CT->GetC_1()->size();i++){
        element_pow_zn(res2, *CT->GetC_1_i(i), *SK->GetX()->At(i + 1));
        element_mul(res1, res1, res2);
    }
    element_div(res1, res1, *e_sk2_c2->At(0));
    element_div(res1, res1, *e_sk1_c4->At(0));

    element_t *res = this->myDlog(res1);

    element_clear(*res);
    element_clear(res1);
    element_clear(res2);
    delete e_sk4_c5;
    delete e_sk1_c4;
    delete e_sk3_c3;
    delete e_sk2_c2;
};


void CP_PK_IPFE::init_dlog(int table_len) {
    this->gslen = 0;
    for(auto kv: this->Dlog_table) element_clear(*kv.second);
    this->Dlog_table.clear();
    this->Dlog_table_len = table_len;
    if(table_len == 0) return;
    element_t base, res, index, adder;
    element_init_same_as(base, *this->PK->GetE_g1_g2());
    element_init_same_as(res, *this->PK->GetE_g1_g2());
    element_init_same_as(index, *this->MSK->GetS_k());
    element_init_same_as(adder, *this->MSK->GetS_k());
    element_set(base, *this->PK->GetE_g1_g2());
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
    element_init_same_as(this->gs_base, *this->PK->GetE_g1_g2());
    element_pow_zn(this->gs_base, *this->PK->GetE_g1_g2(), index);
    element_init_same_as(this->gs_step, index);
    element_set(this->gs_step, index);

    element_clear(base);
    element_clear(res);
    element_clear(index);
    element_clear(adder);
};

void CP_PK_IPFE::init_max_res(int res) {
    if(this->Dlog_table_len == 0) return;
    this->gslen = (res / this->Dlog_table_len) + 1;
};
#include <ibe/CipherText.h>
#include <openssl/sha.h>
#include <utils/func.h>

CipherTextSong::CipherTextSong(PublicKeySong *PK, ElementList *ID, ElementList *x) {
    int n = x->len(), d = PK->GetU()->len() - 1, l = ID->len();
    element_t tmp, r;
    element_init_same_as(r, *x->At(1));
    element_random(r);

    element_init_same_as(this->C_r, *PK->GetG());
    element_pow_zn(this->C_r, *PK->GetG(), r);

    element_init_same_as(tmp, *PK->GetG());
    element_init_same_as(this->C_u, *PK->GetG());
    element_set(this->C_u, *PK->GetU_i(d + 1));
    for(int i = 1; i <= l; i++) {
        element_pow_zn(tmp, *PK->GetU_i(i), *ID->At(i));
        element_mul(this->C_u, this->C_u, tmp);
    }
    element_pow_zn(this->C_u, this->C_u, r);

    this->C_x_i = new ElementList(n, 0, *PK->GetEgg(), false);
    this->HID = new ElementList(ID, 0);
    element_init_same_as(tmp, *PK->GetEgg());
    for(int i = 1;i <= n;i++) {
        element_pow_zn(*this->C_x_i->At(i), *PK->GetEgg(), *x->At(i));
        element_pairing(tmp, *PK->GetG_1(), *PK->GetH_i(i));
        element_pow_zn(tmp, tmp, r);
        element_mul(*this->C_x_i->At(i), *this->C_x_i->At(i), tmp);
    }

    element_clear(tmp);
    element_clear(r);
};

element_t *CipherTextSong::GetC_r() {
    return &this->C_r;
};

element_t *CipherTextSong::GetC_u() {
    return &this->C_u;
};

ElementList *CipherTextSong::GetC_x() {
    return this->C_x_i;
};

ElementList *CipherTextSong::GetHID() {
    return this->HID;
};

element_t *CipherTextSong::GetC_x_i(int i) {
    return this->C_x_i->At(i);
};

std::string CipherTextSong::toString() {
    int buflen = 1024;
    char buf[buflen];
    std::string res = "CipherTextSong类\n", tmp;
    element_snprint(buf, buflen, *this->GetC_r());
    tmp = buf;
    res += "C_r: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetC_u());
    tmp = buf;
    res += "C_u: " + tmp + "\n";
    res += this->C_x_i->toString("n", "C_x_i");
    return res;
};

CipherTextSong::~CipherTextSong() {
    element_clear(C_r);
    element_clear(C_u);
    if(this->C_x_i != NULL) delete this->C_x_i;
    if(this->HID != NULL) delete this->HID;
};

CipherTextWIB::CipherTextWIB(PublicKeyWIB *PK, ElementList *P, ElementList *x, ElementList *E_G_H_1_Z_i, HIDparamWIB *param){
    int n = x->len(), d = P->len();
    element_t tmp, s;
    element_init_same_as(s, *x->At(1));
    element_random(s);
    this->C_x_i = new ElementList(n, 0, *PK->GetEgg(), false);
    this->P = new ElementList(P,0);
    element_init_same_as(tmp, *PK->GetEgg());
    for(int i = 1;i <= n;i++) {
        element_pow_zn(*this->C_x_i->At(i), *PK->GetEgg(), *x->At(i));
        element_pow_zn(tmp, *E_G_H_1_Z_i->At(i), s);
        element_div(*this->C_x_i->At(i), *this->C_x_i->At(i), tmp);
    }

    element_init_same_as(this->C_1, *PK->GetG());
    element_pow_zn(this->C_1, *param->GetG_1_G_C(), s);

    element_init_same_as(this->C_2, *PK->GetEgg());
    element_set(this->C_2, *PK->GetEgg());
    element_pow_zn(this->C_2, this->C_2, s);

    element_init_same_as(this->C_3, *PK->GetG());
    element_pow_zn(this->C_3, *param->GetU_i_H_i_C_Times(), s);

    element_init_same_as(this->C_4, *PK->GetG());
    element_set1(this->C_4);
    for(int i = 1; i <= d; i++){
        if(element_is0(*P->At(i))){
            element_mul(this->C_4, this->C_4, *param->GetU_i_H_i_C(i));
        }
    }
    element_pow_zn(this->C_4, this->C_4, s);
    element_clear(s);
    element_clear(tmp);
};

element_t *CipherTextWIB::GetC_1(){
    return &this->C_1;
};

element_t *CipherTextWIB::GetC_2(){
    return &this->C_2;
};

element_t *CipherTextWIB::GetC_3(){
    return &this->C_3;
};

element_t *CipherTextWIB::GetC_4(){
    return &this->C_4;
};

ElementList *CipherTextWIB::GetC_x(){
    return this->C_x_i;
};

element_t *CipherTextWIB::GetC_x_i(int i){
    return this->C_x_i->At(i);
};

ElementList *CipherTextWIB::GetP(){
    return this -> P;
};

std::string CipherTextWIB::toString(){
    int buflen = 1024;
    char buf[buflen];
    std::string res = "CipherTextCCA类\n", tmp;
    element_snprint(buf, buflen, *this->GetC_1());
    tmp = buf;
    res += "C_1: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetC_2());
    tmp = buf;
    res += "C_2: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetC_3());
    tmp = buf;
    res += "C_3: " + tmp + "\n";
    res += this->C_x_i->toString("n", "C_x_i");
    element_snprint(buf, buflen, *this->GetC_4());
    tmp = buf;
    res += "C_4: " + tmp + "\n";
    return res;
};

CipherTextWIB::~CipherTextWIB(){
    element_clear(C_1);
    element_clear(C_2);
    element_clear(C_3);
    element_clear(C_4);
    if(this->C_x_i != NULL) delete this->C_x_i;
    if(this->P != NULL) delete this->P;
};

CiphertextIBBE::CiphertextIBBE(PublicKeyIBBE *PK, ElementList *S, ElementList *x){
    int s = S->len(), n = x->len();
    element_init_same_as(this->C_0, *PK->GetH());
    element_init_same_as(this->C_1, *PK->GetEgh());
    element_init_same_as(this->C_2, *PK->GetG());
    element_t r, tmp0_0, tmp0_1, tmp1, tmp2, temp1, temp2;
    element_init_same_as(r, *S->At(1));
    element_random(r);
    element_init_same_as(tmp0_0, *S->At(1));
    element_init_same_as(tmp0_1, *S->At(1));
    element_init_same_as(tmp1, *S->At(1));
    element_init_same_as(tmp2, *PK->GetEgh());
    element_init_same_as(temp1, *PK->GetG());
    element_init_same_as(temp2, *PK->GetG());
    element_set(tmp2, *PK->GetEgh());

    this->C_i_1 = new ElementList(n, 0, *PK->GetG(), false);
    this->C_i_2 = new ElementList(n, 0, *PK->GetEgh(), false);

    //TODO: Compute the polynomials (a-ID_1)....(a-ID_s) = a^s + (-1)^{s-1} * C(s,s-1) * a^{s-1} * (ID_1+..ID_s)
    ElementList *ployA = new ElementList(s+1 , 0, *S->At(1), false);
    ElementList *ployB = new ElementList(s+1, 0, *S->At(1), false);
    for(int i = 1; i <= s + 1; i++){
        element_init_same_as(*ployA->At(i), r);
        element_set0(*ployA->At(i));
        element_init_same_as(*ployB->At(i),r);
        element_set0(*ployB->At(i));
    }
    element_set(*ployA->At(1), *S->At(1));
    element_set1(*ployA->At(1));
    for(int i = 2; i <= s+1; i++){
        element_set1(*ployA->At(i+1));
        for(int j = i; j >= 2; j--){
            element_mul(*ployB->At(j), *ployA->At(j), *S->At(i));
            element_mul(*ployA->At(j), *ployA->At(j-1), *ployB->At(j));
        }
        element_mul(*ployA->At(1), *ployA->At(1),*S->At(i));
    }
    element_set1(temp1);
    for(int i = 0; i < s+1; i++){
        element_pow_zn(temp2, *PK->GetH_r_1_alpha_i(i), *ployA->At(i+1));
        element_mul(temp1, temp1, temp2);
    }
    element_set(this->C_2, temp1);
    

    element_pairing(this->C_1, *PK->GetG_r_2_N_2(), *PK->GetH());
    element_pow_zn(this->C_1, this->C_1, r);

    element_pow_zn(this->C_2, *PK->GetG_N_1_alpha(), r);

    for(int i = 1; i <= n; i++){
        element_pow_zn(*this->C_i_1->At(i), *PK->GetG_N_1_alpha_beta_i(i), r);  //g^{n_1ab_i}^r
        element_set1(tmp1);
        element_div(*this->C_i_1->At(1), tmp1, *this->C_i_1->At(i));

        element_pairing(*this->C_i_2->At(i), *PK->GetG_r_2_N_2(), *PK->GetH_beta_i(i));
        element_pow_zn(*this->C_i_2->At(i), *this->C_i_2->At(i), r);
        element_pow_zn(tmp2, tmp2, *x->At(i));
        element_mul(*this->C_i_2->At(i), *this->C_i_2->At(i), tmp2);
    }

    element_clear(r);
    element_clear(tmp0_0);
    element_clear(tmp0_1);
    element_clear(tmp1);
    element_clear(tmp2);

    if(ployA != NULL) delete ployA;
    if(ployB != NULL) delete ployB;
};

element_t *CiphertextIBBE::GetC_0(){
    return &this->C_0;
};

element_t *CiphertextIBBE::GetC_1(){
    return &this->C_1;
};

element_t *CiphertextIBBE::GetC_2(){
    return &this->C_2;
};

ElementList *CiphertextIBBE::GetC_i_1(){
    return this->C_i_1;
};

ElementList *CiphertextIBBE::GetC_i_2(){
    return this->C_i_2;
};

element_t *CiphertextIBBE::GetC_i_1_i(int i){
    return this->C_i_1->At(i);
};

element_t *CiphertextIBBE::GetC_i_2_i(int i){
    return this->C_i_2->At(i);
};

std::string CiphertextIBBE::toString(){
    int buflen = 1024;
    char buf[buflen];
    std::string res = "CipherTextCCA类\n", tmp;
    element_snprint(buf, buflen, *this->GetC_0());
    tmp = buf;
    res += "C_0: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetC_1());
    tmp = buf;
    res += "C_1: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetC_2());
    tmp = buf;
    res += "C_2: " + tmp + "\n";
    res += this->C_i_1->toString("n", "C_i_1");
    res += this->C_i_2->toString("n", "C_i_2");
    return res;
};

CiphertextIBBE::~CiphertextIBBE(){
    if(this->C_i_1 != NULL) delete this->C_i_1;
    if(this->C_i_2 != NULL) delete this->C_i_2;
    element_clear(this->C_0);
    element_clear(this->C_1);
    element_clear(this->C_2);
    this->C_i_1 = NULL;
    this->C_i_2 = NULL;
};

//TODO: CP
CiphertextCP::CiphertextCP(PublicKeyCP *PK, ElementList *a_c, ElementList *y, std::string policy){
    policy_resolution pr;
    policy_generation pg;
    utils util;
    
    element_t s_c;
    element_init_same_as(s_c, *y->At(1));
    element_random(s_c);
    element_init_same_as(this->c_4, *PK->GetG_2());
    element_pow_zn(this->c_4, *PK->GetG_2(), s_c);

    element_t sample_element;
    element_init_same_as(sample_element, s_c);
    element_random(sample_element);

    this->policy = policy;

    // compute access structure
    multiway_tree *T = pr.ThresholdExpressionToMultiwayTree(policy, sample_element);
    pg.generatePolicyInMultiwayTreeForm(T, s_c);

    // compute c_1
    this->c_1 = new std::vector<element_t>(y->len());
    element_t tmp1, tmp2;
    element_init_same_as(tmp1, *PK->GetE_g1_g2());
    element_init_same_as(tmp2, *PK->GetE_g1_g2());
    element_set1(tmp2);
    for(int i = 0; i < y->len(); i++){
        element_init_same_as(this->c_1->at(i), *PK->GetE_g1_g2());
        element_pow_zn(this->c_1->at(i), this->c_1->at(i), *y->At(i+1));
        for(int j =  1; j <= y->len(); j++){
            element_pow_zn(tmp1, *PK->GetE_g1_g2_sk_F_i_j(i,j), *a_c->At(j));
            element_mul(tmp2, tmp1, tmp2);
        }
        element_pow_zn(tmp2, tmp2, s_c);
        element_mul(this->c_1->at(i), this->c_1->at(i), tmp2);
        element_set1(tmp2);
    }

    //compute c_2, c_3 and c_5
    this->c_2 = new std::vector<element_t>;
    this->c_3 = new std::vector<element_t>;
    this->c_5 = new std::vector<element_t>;

    queue<multiway_tree_node*> q;
    q.push(T->getRoot());
    while (!q.empty()) {
        if (q.front()->getType() == multiway_tree_node::LEAF) {
            // get qc
            element_t qc;
            element_init_same_as(qc, s_c);
            element_set(qc, q.front()->getValue());

            // get attribute
            string att = q.front()->getName();

            // compute Hash(attribute)
            element_t H1_att, H2_att;
            element_init_same_as(H1_att, *PK->GetG_1());
            element_init_same_as(H2_att, *PK->GetG_2());
            element_set(H1_att, util.stringToElementT(att, *PK->GetG_1()));
            element_set(H2_att, util.stringToElementT(att, *PK->GetG_2()));
            
            //compute c_2
            element_t tmp3;
            element_init_same_as(tmp3, *PK->GetG_1());
            element_pow_zn(tmp3, *PK->GetG_1(), qc);
            //this->c_2->push_back(tmp3);
            element_clear(tmp3);

            //compute c_3
            element_t tmp4;
            element_init_same_as(tmp4, *PK->GetG_2());
            element_pow_zn(tmp4, H2_att, qc);
            element_clear(tmp4);

            //compute c_5
            element_t tmp5;
            element_init_same_as(tmp5, *PK->GetG_1());
            element_pow_zn(tmp5, H1_att, qc);
            //this->c_5->push_back(tmp5);
            element_clear(tmp5);
        }
        if (q.front()->getFirstChild() != NULL) {
            multiway_tree_node* child = q.front()->getFirstChild();
            while (NULL != child) {
                q.push(child);
                child = child->getNextSibling();
            }
        }
        q.pop();
    }

    element_clear(s_c);
    element_clear(sample_element);
    element_clear(tmp1);
    element_clear(tmp2);
};


access_structure *CiphertextCP::getAccessStructure(){
    return this->A;
};

void CiphertextCP::setPolicy(string policy){
    this->policy = policy;
};

string CiphertextCP::getPolicy(){
    return this->policy;
};

element_t *CiphertextCP::GetC_4(){
    return &this->c_4;
};

std::vector<element_t> *CiphertextCP::GetC_1(){
    return this->c_1;
};

element_t *CiphertextCP::GetC_1_i(int i){
    return &this->c_1->at(i);
};

std::vector<element_t> *CiphertextCP::GetC_2(){
    return this->c_2;
};

element_t *CiphertextCP::GetC_2_i(int i){
    return &this->c_2->at(i);
};
    
std::vector<element_t> *CiphertextCP::GetC_3(){
    return this->c_3;
};

element_t *CiphertextCP::GetC_3_i(int i){
    return &this->c_3->at(i);
};
    
std::vector<element_t> *CiphertextCP::GetC_5(){
    return this->c_5;
};

element_t *CiphertextCP::GetC_5_i(int i){
    return &this->c_5->at(i);
};

std::string CiphertextCP::toString(){
    int buflen = 1024;
    char buf[buflen];
    std::string res = "CipherTextCP类\n", tmp;

    res += "c_1\n";
    for(int i = 0; i < (int) c_1->size(); i++){
        res += std::to_string(i + 1) + ": ";
        element_snprint(buf, buflen, this->c_1->at(i));
        tmp = buf;
        res += tmp + "\n";
    }

    res += "c_2\n";
    for(int i = 0; i < (int) c_2->size(); i++){
        res += std::to_string(i + 1) + ": ";
        element_snprint(buf, buflen, this->c_2->at(i));
        tmp = buf;
        res += tmp + "\n";
    }

    res += "c_3\n";
    for(int i = 0; i < (int) c_3->size(); i++){
        res += std::to_string(i + 1) + ": ";
        element_snprint(buf, buflen, this->c_3->at(i));
        tmp = buf;
        res += tmp + "\n";
    }

    element_snprint(buf, buflen, *this->GetC_4());
    tmp = buf;
    res += "c_4: " + tmp + "\n";

    res += "c_5\n";
    for(int i = 0; i < (int) c_5->size(); i++){
        res += std::to_string(i + 1) + ": ";
        element_snprint(buf, buflen, this->c_5->at(i));
        tmp = buf;
        res += tmp + "\n";
    }

    return res;
};

CiphertextCP::~CiphertextCP(){
    element_clear(this->c_4);
    if(this->c_1 != NULL){
        for(int i = 0; i < (int) c_1->size(); i++){
            element_clear(this->c_1->at(i));
        }
        this->c_1->clear();
        delete this->c_1;
    }
    if(this->c_2 != NULL){
        for(int i = 0; i < (int) c_2->size(); i++){
            element_clear(this->c_2->at(i));
        }
        this->c_2->clear();
        delete this->c_2;
    }
    if(this->c_3 != NULL){
        for(int i = 0; i < (int) c_3->size(); i++){
            element_clear(this->c_3->at(i));
        }
        this->c_3->clear();
        delete this->c_3;
    }
    if(this->c_5 != NULL){
        for(int i = 0; i < (int) c_5->size(); i++){
            element_clear(this->c_5->at(i));
        }
        this->c_5->clear();
        delete this->c_5;
    }
};
#include <ibe/PublicKey.h>

PublicKeySong::PublicKeySong(int n, int d, pairing_t &pairing, element_t &MSK)
{
    element_init_G1(this->g, pairing);
    element_init_G1(this->g_1, pairing);
    element_init_GT(this->egg, pairing);
    element_random(this->g);
    element_pow_zn(this->g_1, this->g, MSK);
    element_pairing(this->egg, this->g, this->g);

    this->h_i = new ElementList(n, 0, this->g, true);
    this->u_i = new ElementList(d + 1, 0, this->g, true);
}

element_t *PublicKeySong::GetG()
{
    return &this->g;
};

element_t *PublicKeySong::GetEgg()
{
    return &this->egg;
};

element_t *PublicKeySong::GetG_1()
{
    return &this->g_1;
};

ElementList *PublicKeySong::GetH()
{
    return this->h_i;
};

ElementList *PublicKeySong::GetU()
{
    return this->u_i;
};

element_t *PublicKeySong::GetH_i(int i)
{
    return this->h_i->At(i);
};

element_t *PublicKeySong::GetU_i(int i)
{
    return this->u_i->At(i);
};

std::string PublicKeySong::toString()
{
    int buflen = 1024;
    char buf[buflen];
    std::string res = "PublicKeySong类\n", tmp;
    element_snprint(buf, buflen, *this->GetG());
    tmp = buf;
    res += "g: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetG_1());
    tmp = buf;
    res += "g_1: " + tmp + "\n";
    res += this->h_i->toString("d", "h");
    res += this->u_i->toString("d - 1", "u");
    return res;
};

PublicKeySong::~PublicKeySong()
{
    if (this->h_i != NULL)
        delete this->h_i;
    if (this->u_i != NULL)
        delete this->u_i;
    element_clear(this->g);
    element_clear(this->g_1);
    element_clear(this->egg);
};

PublicKeyWIB::PublicKeyWIB(int n, int d, pairing_t &pairing, MasterKeyWIB *MSK){
    element_init_G1(this->g, pairing);
    element_init_G1(this->g_1, pairing);
    element_init_G1(this->h_1_line, pairing);
    element_init_GT(this->egg, pairing);
    element_init_Zr(this->c, pairing);
    element_random(this->g);
    element_random(this->c);
    element_random(this->h_1_line);
    element_pow_zn(this->g_1,this->g,*MSK->GetAlpha());
    element_pairing(this->egg, this->g, this->g);

    this->h_i = new ElementList(d, 0, this->g, true);
    this->u_i = new ElementList(d, 0, this->g, false);
    for(int i = 1; i <= d; i++){
        element_pow_zn(*this->GetU_i(i), *this->GetH_i(i), *MSK->GetAlpha());
    }
    this->h_1z_i = new ElementList(n, 0, this->g, false);
    for(int i = 1; i <= n;++i){
        element_pow_zn(*this->GetH_1_Z_i(i), this->h_1_line, *MSK->GetZ_i(i));
    }
};

element_t *PublicKeyWIB::GetG(){
    return &this->g;
};

element_t *PublicKeyWIB::GetC(){
    return &this->c;
};

element_t *PublicKeyWIB::GetEgg(){
    return &this->egg;
};

element_t *PublicKeyWIB::GetG_1(){
    return &this->g_1;
};

element_t *PublicKeyWIB::GetH_1_line(){
    return &this->h_1_line;
};

ElementList *PublicKeyWIB::GetH(){
    return this->h_i;
};

ElementList *PublicKeyWIB::GetU(){
    return this->u_i;
};

ElementList *PublicKeyWIB::GetH_1Z(){
    return this->h_1z_i;
};

element_t *PublicKeyWIB::GetH_i(int i){
    return this->h_i->At(i);
};

element_t *PublicKeyWIB::GetU_i(int i){
    return this->u_i->At(i);
};

element_t *PublicKeyWIB::GetH_1_Z_i(int i){
    return this->h_1z_i->At(i);
};

std::string PublicKeyWIB::toString(){
    int buflen = 1024;
    char buf[buflen];
    std::string res = "PublicKeyWIB类\n", tmp;
    element_snprint(buf, buflen, *this->GetG());
    tmp = buf;
    res += "g: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetG_1());
    tmp = buf;
    res += "g_1: " + tmp + "\n";
    res += this->h_i->toString("d", "h");
    res += this->u_i->toString("d - 1", "u");
    res += this->h_1z_i->toString("n", "h1^zi");
    return res;
};

PublicKeyWIB::~PublicKeyWIB(){
    if(this->h_i != NULL) delete this->h_i;
    if(this->u_i != NULL) delete this->u_i;
    if(this->h_1z_i !=NULL) delete this->h_1z_i;
    element_clear(this->g);
    element_clear(this->g_1);
    element_clear(this->egg);
    element_clear(this->c);
    element_clear(this->h_1_line);
};

//TODO: IBBE
PublicKeyIBBE::PublicKeyIBBE(int n, pairing_t &pairing, MasterKeyIBBE *MSK){
    element_init_G1(this->g, pairing);
    element_init_G1(this->h, pairing);
    element_init_GT(this->egh, pairing);
    element_random(this->g);
    element_random(this->h);
    element_pairing(this->egh, this->g, this->h);
    element_init_same_as(this->g_n_1_alpha, this->g);
    element_init_same_as(this->g_r_2_n_2, this->g);
    element_pow_zn(this->g_n_1_alpha, this->g, *MSK->GetN_1());
    element_pow_zn(this->g_n_1_alpha, *this->GetG_N_1_alpha(), *MSK->GetAlpha());     //g^{n_1 \alpha}
    element_pow_zn(this->g_r_2_n_2, this->g, *MSK->GetR_2());
    element_pow_zn(this->g_r_2_n_2, this->g_r_2_n_2, *MSK->GetN_2());       //g^{r_2n_2}
    element_t tmp1;
    element_init_same_as(tmp1, *MSK->GetAlpha());
    element_set(tmp1, *MSK->GetAlpha());    //tmp -> a^1

    this->g_n_1_alpha_beta = new ElementList(n, 0, this->g, false);
    this->h_r_1_alpha = new ElementList(n + 1, -1, this->h, false);
    this->h_beta = new ElementList(n, 0, this->h, false);



    element_pow_zn(*this->GetH_r_1_alpha_i(n), this->h, *MSK->GetR_1());      //h^{r_1}
    element_set(*this->GetH_r_1_alpha_i(0), *this->GetH_r_1_alpha_i(n)); 

    for(int i = 1; i <= n; ++i){
        element_pow_zn(*this->GetG_N_1_alpha_beta_i(i), *this->GetG_N_1_alpha_beta_i(n), *MSK->GetBeta_i(i));

        element_pow_zn(*this->GetH_r_1_alpha_i(i), *this->GetH_r_1_alpha_i(n), tmp1);
        element_mul(tmp1, tmp1, tmp1);  //a^i -> a^{i+1}

        element_pow_zn(*this->GetH_beta_i(i), this->h, *MSK->GetBeta_i(i));
    }

    element_clear(tmp1);
};

element_t *PublicKeyIBBE::GetH(){
    return &this->h;
};

element_t *PublicKeyIBBE::GetG(){
    return &this->g;
};

element_t *PublicKeyIBBE::GetG_N_1_alpha(){
    return &this->g_n_1_alpha;
};

element_t *PublicKeyIBBE::GetG_r_2_N_2(){
    return &this->g_r_2_n_2;
};

element_t *PublicKeyIBBE::GetEgh(){
    return &this->egh;
};

ElementList *PublicKeyIBBE::GetG_N_1_alpha_beta(){
    return this->g_n_1_alpha_beta;
};

ElementList *PublicKeyIBBE::GetH_r_1_alpha(){
    return this->h_r_1_alpha;
};

ElementList *PublicKeyIBBE::GetH_beta(){
    return this->h_beta;
};

element_t *PublicKeyIBBE::GetG_N_1_alpha_beta_i(int i){
    return this->g_n_1_alpha_beta->At(i);
};

element_t *PublicKeyIBBE::GetH_r_1_alpha_i(int i){
    return this->h_r_1_alpha->At(i);
};

element_t *PublicKeyIBBE::GetH_beta_i(int i){
    return this->h_beta->At(i);
};

std::string PublicKeyIBBE::toString(){
    int buflen = 1024;
    char buf[buflen];
    std::string res = "PublicKeyIBBE类\n", tmp;
    element_snprint(buf, buflen, *this->GetH());
    tmp = buf;
    res += "h: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetG());
    tmp = buf;
    res += "g: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetG_N_1_alpha());
    tmp = buf;
    res += "g^{n_1_a}: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetG_r_2_N_2());
    tmp = buf;
    res += "g^{r_2n_2}: " + tmp + "\n";
    
    res += this->g_n_1_alpha_beta->toString("n", "g^{n_1_a_b_i}");
    res += this->h_r_1_alpha->toString("n", "h^{r_1 a^i}");
    res += this->h_beta->toString("n", "h^{b_i}");
    return res;
};

PublicKeyIBBE::~PublicKeyIBBE(){
    if(this->g_n_1_alpha_beta != NULL) delete this->g_n_1_alpha_beta;
    if(this->h_r_1_alpha != NULL) delete this->h_r_1_alpha;
    if(this->h_beta !=NULL) delete this->h_beta;
    element_clear(h);
    element_clear(this->g);
    element_clear(this->g_n_1_alpha);
    element_clear(this->g_r_2_n_2);
};

//TODO: CP
PublicKeyCP::PublicKeyCP(int n, pairing_t &pairing, MasterKeyCP *MSK){
    this->n = n;
    element_init_G1(this->g_1, pairing);
    element_init_G2(this->g_2, pairing);
    element_init_GT(this->eg_1g_2, pairing);
    element_set(this->g_1, *MSK->GetG_1());
    element_set(this->g_2, *MSK->GetG_2());
    element_set(this->eg_1g_2, *MSK->GetE_g1_g2());

    element_t tmp;
    element_init_same_as(tmp, *MSK->GetS_k());
    for(int i = 0; i < n; i++){
        this->eg_1g_2_s_kF[i] = new ElementList(n - i, 0, this->eg_1g_2, false);
        for(int j = 1; j <= n -i ; j++){
            element_mul(tmp, *MSK->GetS_k(), *MSK->GetF_i_j(i, j));
            element_pow_zn(*this->eg_1g_2_s_kF[i]->At(j), this->eg_1g_2, tmp);
        }
    }
    element_clear(tmp);
};

element_t *PublicKeyCP::GetG_1(){
    return &this->g_1;
};

element_t *PublicKeyCP::GetG_2(){
    return &this->g_2;
};

element_t *PublicKeyCP::GetE_g1_g2(){
    return &this->eg_1g_2;
};  

ElementList *PublicKeyCP::GetE_g1_g2_sk_F_i(int i){
    return this->eg_1g_2_s_kF[i];
};

element_t *PublicKeyCP::GetE_g1_g2_sk_F_i_j(int i, int j){
    if(i > j){
        return this->eg_1g_2_s_kF[j]->At(i);
    }
    return this->eg_1g_2_s_kF[i]->At(j);
};

std::string PublicKeyCP::toString(){
    int buflen = 1024;
    char buf[buflen];
    std::string res = "PublicKeyCP类\n", tmp;
    element_snprint(buf, buflen, *this->GetG_1());
    tmp = buf;
    res += "g_1: " + tmp + "\n";

    element_snprint(buf, buflen, *this->GetG_2());
    tmp = buf;
    res += "g_2: " + tmp + "\n";

    for(int i = 0; i < this->n; i++){
        res += this->eg_1g_2_s_kF[i]->toString(std::to_string(i + 1), "e_g1_g2_sk_F_i");
        res += "\n";
    }
    return res;
};

PublicKeyCP::~PublicKeyCP(){
    element_clear(this->g_1);
    element_clear(this->g_2);
    element_clear(this->eg_1g_2);
    for(int i = 0; i < this->n; i++){
        if(this->eg_1g_2_s_kF[i] != NULL){
            delete eg_1g_2_s_kF[i];
            eg_1g_2_s_kF[i] = NULL;
        }
    }
};
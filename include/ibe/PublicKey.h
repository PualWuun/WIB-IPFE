#ifndef PUBLIC_KEY_H
#define PUBLIC_KEY_H

#include <pbc/pbc.h>
#include <ibe/ElementList.h>
#include <ibe/MasterKey.h>

class PublicKeySong
{
private:
    element_t g, g_1, egg;
    ElementList *h_i, *u_i;

public:
    PublicKeySong(int n, int d, pairing_t &pairing, element_t &MSK);

    element_t *GetG();

    element_t *GetEgg();

    element_t *GetG_1();

    ElementList *GetH();

    ElementList *GetU();

    element_t *GetH_i(int i);

    element_t *GetU_i(int i);

    std::string toString();

    ~PublicKeySong();
};

//TODO: WIB
class PublicKeyWIB
{
private:
    element_t c, g, g_1, egg, h_1_line;
    ElementList *h_i, *u_i, *h_1z_i;

public:
    PublicKeyWIB(int n, int d, pairing_t &pairing, MasterKeyWIB *MSK);

    element_t *GetC();

    element_t *GetG();

    element_t *GetEgg();

    element_t *GetH_1_line();

    element_t *GetG_1();

    ElementList *GetH();

    ElementList *GetU();

    ElementList *GetH_1Z();

    element_t *GetH_i(int i);

    element_t *GetU_i(int i);

    element_t *GetH_1_Z_i(int i);

    std::string toString();

    ~PublicKeyWIB();
};


//TODO: IBBE
class PublicKeyIBBE{
private:
    element_t h, g, g_n_1_alpha, g_r_2_n_2, egh;
    ElementList *g_n_1_alpha_beta, *h_r_1_alpha, *h_beta;
    long long c_res[50][50] = {0};

public:
    PublicKeyIBBE(int n, pairing_t &pairing, MasterKeyIBBE *MSK);

    element_t *GetH();

    element_t *GetG();

    element_t *GetG_N_1_alpha();

    element_t *GetG_r_2_N_2();

    element_t *GetEgh();

    ElementList *GetG_N_1_alpha_beta();

    ElementList *GetH_r_1_alpha();

    ElementList *GetH_beta();

    element_t *GetG_N_1_alpha_beta_i(int i);

    element_t *GetH_r_1_alpha_i(int i);

    element_t *GetH_beta_i(int i);

    long long C(int s, int i);

    std::string toString();

    ~PublicKeyIBBE();

};
#endif // PUBLIC_KEY_H
#ifndef MASTER_KEY_H
#define MASTER_KEY_H

#include <pbc/pbc.h>
#include <ibe/ElementList.h>
#include <string>
#include <vector>

class MasterKey
{
private:
    element_t alpha;
    ElementList *z;

public:
    MasterKey(int n, pairing_t &pairing);

    element_t *GetAlpha();

    ElementList *GetZ();

    element_t *GetZ_i(int i);

    std::string toString();

    ~MasterKey();
};

class MasterKeyWIB
{
private:
    element_t alpha, r_1;
    ElementList *z;

public:
    MasterKeyWIB(int n, pairing_t &pairing);

    element_t *GetAlpha();

    element_t *GetR_1();

    ElementList *GetZ();

    element_t *GetZ_i(int i);

    std::string toString();

    ~MasterKeyWIB();
};

class MasterKeyIBBE{
private:
    element_t alpha, r_1, r_2, n_1, n_2;
    ElementList *beta;

public:
    MasterKeyIBBE(int n, pairing_t &pairing);

    element_t *GetAlpha();

    element_t *GetR_1();

    element_t *GetR_2();

    element_t *GetN_1();

    element_t *GetN_2();

    ElementList *GetBeta();

    element_t *GetBeta_i(int i);

    std::string toString();

    ~MasterKeyIBBE();
};


class MasterKeyCP{
private:
    int n;
    element_t s_k, g_1, g_2, eg_1g_2;
    std::vector<ElementList *> F;
    /* 1 2 3
       - 4 5
       - - 6*/

public:
    MasterKeyCP(int n, pairing_t &pairing);

    element_t *GetS_k();

    element_t *GetG_1();

    element_t *GetG_2();

    element_t *GetE_g1_g2();

    ElementList *GetF_i(int i);

    element_t *GetF_i_j(int i, int j);

    std::string toString();

    ~MasterKeyCP();
};
#endif // MASTER_KEY_H
#ifndef MASTER_KEY_H
#define MASTER_KEY_H

#include <pbc/pbc.h>
#include <ibe/ElementList.h>
#include <string>

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

#endif // MASTER_KEY_H
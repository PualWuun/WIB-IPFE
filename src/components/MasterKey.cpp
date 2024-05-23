#include "ibe/MasterKey.h"

MasterKey::MasterKey(int n, pairing_t &pairing)
{
    element_init_Zr(this->alpha, pairing);
    element_random(this->alpha);
    this->z = new ElementList(n, 0, this->alpha, true);
};

element_t *MasterKey::GetAlpha()
{
    return &this->alpha;
};

ElementList *MasterKey::GetZ()
{
    return this->z;
};

element_t *MasterKey::GetZ_i(int i)
{
    return this->z->At(i);
};

std::string MasterKey::toString()
{
    int buflen = 1024;
    char buf[buflen];
    std::string res = "MasterKey类\n", tmp;
    element_snprint(buf, buflen, *this->GetAlpha());
    tmp = buf;
    res += "alpha: " + tmp + "\n";
    res += this->z->toString("n", "z");
    return res;
};
MasterKey::~MasterKey()
{
    if (this->z != NULL)
        delete this->z;
    element_clear(this->alpha);
};

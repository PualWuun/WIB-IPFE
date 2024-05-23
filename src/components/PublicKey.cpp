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
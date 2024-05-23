#include <ibe/SecretKey.h>

SecretKeySong::SecretKeySong(PublicKeySong *PK, element_t &MSK, ElementList *ID, ElementList *y) {
    this->y = new ElementList(y, 0);
    this->HID = new ElementList(ID, 0);
    int l = ID->len(), n = y->len(), d = PK->GetU()->len() - 1;
    element_t t, res1, res2;
    element_init_same_as(t, MSK);
    element_random(t);

    element_init_same_as(res1, *PK->GetG());
    element_init_same_as(res2, *PK->GetG());
    element_set(res1, *PK->GetU_i(d + 1));
    for(int i = 1; i <= l; i++) {
        element_pow_zn(res2, *PK->GetU_i(i), *ID->At(i));
        element_mul(res1, res1, res2);
    }
    element_pow_zn(res1, res1, t);
    element_init_same_as(this->K_h, *PK->GetG());

    for(int i = 1; i <= n; i++) {
        element_pow_zn(res2, *PK->GetH_i(i), *y->At(i));
        element_mul(this->K_h, this->K_h, res2);
    }
    element_pow_zn(this->K_h, this->K_h, MSK);
    element_div(this->K_h, this->K_h, res1);

    element_init_same_as(this->K_t, *PK->GetG());
    element_pow_zn(this->K_t, *PK->GetG(), t);

    this->K_i = new ElementList(d, l, *PK->GetG(), false);
    for(int i = l + 1;i <= d;i++) element_pow_zn(*this->K_i->At(i), *PK->GetU_i(i), t);

    element_clear(t);
    element_clear(res1);
    element_clear(res2);
}   

SecretKeySong::SecretKeySong(PublicKeySong *PK, SecretKeySong *SK, element_t &IDl) {
    this->y = new ElementList(SK->GetY(), 0);
    this->HID = new ElementList(SK->GetID(), 0);
    this->HID->add(IDl);
    int l = SK->GetID()->len();
    int n = SK->GetY()->len();
    int d = PK->GetU()->len() - 1;
    element_t t, res1, res2;
    element_init_same_as(t, *this->y->At(1));
    element_random(t);

    element_init_same_as(res1, *PK->GetG());
    element_init_same_as(res2, *PK->GetG());
    element_set(res1, *PK->GetU_i(d + 1));
    for(int i = 1; i <= l + 1; i++) {
        element_pow_zn(res2, *PK->GetU_i(i), *this->HID->At(i));
        element_mul(res1, res1, res2);
    }
    element_pow_zn(res1, res1, t);

    element_init_same_as(this->K_h, *PK->GetG());
    element_pow_zn(this->K_h, *SK->GetK_i(l + 1), *this->HID->At(l + 1));
    element_div(this->K_h, *SK->GetK_h(), this->K_h);
    element_div(this->K_h, this->K_h, res1);

    element_init_same_as(this->K_t, *PK->GetG());
    element_pow_zn(this->K_t, *PK->GetG(), t);
    element_mul(this->K_t, this->K_t, *SK->GetK_t());

    this->K_i = new ElementList(d, l + 1, *PK->GetG(), false);
    for(int i = l + 2;i <= d;i++) {
        element_pow_zn(*this->K_i->At(i), *PK->GetU_i(i), t);
        element_mul(*this->K_i->At(i), *this->K_i->At(i), *SK->GetK_i(i));
    }

    element_clear(t);
    element_clear(res1);
    element_clear(res2);
};

element_t *SecretKeySong::GetK_h() {
    return &this->K_h;
};

element_t *SecretKeySong::GetK_t() {
    return &this->K_t;
};

ElementList *SecretKeySong::GetK() {
    return this->K_i;
};

ElementList *SecretKeySong::GetID() {
    return this->HID;
};

ElementList *SecretKeySong::GetY() {
    return this->y;
};

element_t *SecretKeySong::GetID_i(int i) {
    return this->HID->At(i);
};

element_t *SecretKeySong::GetY_i(int i) {
    return this->y->At(i);
};

element_t *SecretKeySong::GetK_i(int i) {
    return this->K_i->At(i);
};

std::string SecretKeySong::toString() {
    int buflen = 1024;
    char buf[buflen];
    std::string res = "SecretKeySong类\n", tmp;
    element_snprint(buf, buflen, *this->GetK_h());
    tmp = buf;
    res += "K_h: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetK_t());
    tmp = buf;
    res += "K_t: " + tmp + "\n";
    res += this->y->toString("n", "y");
    res += this->K_i->toString("d", "K_i");
    return res;
};

SecretKeySong::~SecretKeySong() {
    if(this->HID != NULL) delete this->HID;
    if(this->y != NULL) delete this->y;
    if(this->K_i != NULL) delete this->K_i;
};

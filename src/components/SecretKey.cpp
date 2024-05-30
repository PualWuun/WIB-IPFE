#include <ibe/SecretKey.h>

SecretKeySong::SecretKeySong(PublicKeySong *PK, element_t &MSK, ElementList *ID, ElementList *y)
{
    this->y = new ElementList(y, 0);
    this->HID = new ElementList(ID, 0);
    int l = ID->len(), n = y->len(), d = PK->GetU()->len() - 1;
    element_t t, res1, res2;
    element_init_same_as(t, MSK);
    element_random(t);

    element_init_same_as(res1, *PK->GetG());
    element_init_same_as(res2, *PK->GetG());
    element_set(res1, *PK->GetU_i(d + 1));
    for (int i = 1; i <= l; i++)
    {
        element_pow_zn(res2, *PK->GetU_i(i), *ID->At(i));
        element_mul(res1, res1, res2);
    }
    element_pow_zn(res1, res1, t);
    element_init_same_as(this->K_h, *PK->GetG());

    for (int i = 1; i <= n; i++)
    {
        element_pow_zn(res2, *PK->GetH_i(i), *y->At(i));
        element_mul(this->K_h, this->K_h, res2);
    }
    element_pow_zn(this->K_h, this->K_h, MSK);
    element_div(this->K_h, this->K_h, res1);

    element_init_same_as(this->K_t, *PK->GetG());
    element_pow_zn(this->K_t, *PK->GetG(), t);

    this->K_i = new ElementList(d, l, *PK->GetG(), false);
    for (int i = l + 1; i <= d; i++)
        element_pow_zn(*this->K_i->At(i), *PK->GetU_i(i), t);

    element_clear(t);
    element_clear(res1);
    element_clear(res2);
}

SecretKeySong::SecretKeySong(PublicKeySong *PK, SecretKeySong *SK, element_t &IDl)
{
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
    for (int i = 1; i <= l + 1; i++)
    {
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
    for (int i = l + 2; i <= d; i++)
    {
        element_pow_zn(*this->K_i->At(i), *PK->GetU_i(i), t);
        element_mul(*this->K_i->At(i), *this->K_i->At(i), *SK->GetK_i(i));
    }

    element_clear(t);
    element_clear(res1);
    element_clear(res2);
};

element_t *SecretKeySong::GetK_h()
{
    return &this->K_h;
};

element_t *SecretKeySong::GetK_t()
{
    return &this->K_t;
};

ElementList *SecretKeySong::GetK()
{
    return this->K_i;
};

ElementList *SecretKeySong::GetID()
{
    return this->HID;
};

ElementList *SecretKeySong::GetY()
{
    return this->y;
};

element_t *SecretKeySong::GetID_i(int i)
{
    return this->HID->At(i);
};

element_t *SecretKeySong::GetY_i(int i)
{
    return this->y->At(i);
};

element_t *SecretKeySong::GetK_i(int i)
{
    return this->K_i->At(i);
};

std::string SecretKeySong::toString()
{
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

SecretKeySong::~SecretKeySong()
{
    if (this->HID != NULL)
        delete this->HID;
    if (this->y != NULL)
        delete this->y;
    if (this->K_i != NULL)
        delete this->K_i;
};

// TODO: WIB
SecretKeyWIB::SecretKeyWIB(PublicKeyWIB *PK, MasterKeyWIB *MSK, ElementList *P, ElementList *y, HIDparamWIB *param)
{
    this->y = new ElementList(y, 0);
    this->P = new ElementList(P, 0);
    int l = P->len(), n = y->len(), d = l;
    element_t r, t, res1, res2, res3, tmp1, tmp2;
    element_init_same_as(r, *MSK->GetAlpha());
    element_random(r);
    element_init_same_as(t, *MSK->GetAlpha());
    element_random(t);
    element_init_same_as(tmp1, *PK->GetH_1_line());
    element_init_same_as(tmp2, *PK->GetH_1_line());
    element_init_same_as(res3, *MSK->GetAlpha());
    element_init_same_as(res2, *MSK->GetAlpha());
    element_init_same_as(res1, *MSK->GetAlpha());

    element_set0(res1);
    for (int i = 1; i <= n; i++)
    {
        element_mul(res2, *MSK->GetZ_i(i), *y->At(i));
        element_add(res1, res1, res2);
    } // res1 = <z,y>

    element_sub(res3, *MSK->GetAlpha(), *PK->GetC()); // res3 = a-c
    element_invert(res2, res3);                       // 1/(a-c)
    element_mul(res2, res2, res1);                    // <z,y>/(a-c)

    element_init_same_as(this->r_1_zy, *MSK->GetAlpha());
    element_set1(this->r_1_zy);
    element_mul(this->r_1_zy, *MSK->GetR_1(), res1); // r_1<z,y>

    element_pow_zn(tmp1, *PK->GetG(), *MSK->GetR_1()); // g^r_1
    element_div(tmp1, *PK->GetH_1_line(), tmp1);       // h_1_g^{-r_1}
    element_pow_zn(tmp1, tmp1, res2);                  // tmp1 = (h_1_g^{-r_1})^{<z,y>/(a-c)}

    element_pow_zn(tmp2, *param->GetU_i_H_i_C_Times(), r); // tmp2 = prod
    this->a_i = new ElementList(3, 0, *PK->GetG(), false);
    element_mul(*this->a_i->At(1), tmp1, tmp2); // a_1

    element_pow_zn(*this->a_i->At(2), *PK->GetG(), res3);
    element_pow_zn(*this->a_i->At(2), *this->a_i->At(2), r); // a_2

    element_pow_zn(*this->a_i->At(3), *PK->GetG(), res3);
    element_pow_zn(*this->a_i->At(3), *this->a_i->At(2), t); // a_3

    this->b_i = new ElementList(d, 0, *PK->GetG(), false);
    this->c_i = new ElementList(d, 0, *PK->GetG(), false);
    this->d_i = new ElementList(d, 0, *PK->GetG(), false);

    for (int i = 1; i <= d; i++)
    {
        element_pow_zn(*this->b_i->At(i), *param->GetU_i_H_i_C(i), r);
        element_pow_zn(*this->c_i->At(i), *param->GetU_i_H_i_C(i), t);

            
        if(!element_is0(*P->At(i))){
            element_pow_zn(*this->d_i->At(i), *param->GetU_i_H_i_C_P_i(i),r);
            element_div(*this->d_i->At(i), *this->c_i->At(i), *this->d_i->At(i));
            element_set0(*this->b_i->At(i));
            element_set0(*this->c_i->At(i));
        }
        else{
            element_set0(*this->d_i->At(i));    //?
        }
    }

    element_clear(r);
    element_clear(t);
    element_clear(res1);
    element_clear(res2);
    element_clear(res3);
    element_clear(tmp1);
    element_clear(tmp2);
};

SecretKeyWIB::SecretKeyWIB(PublicKeyWIB *PK, SecretKeyWIB *SK, ElementList *P_new, HIDparamWIB *param){
    int l = P_new->len(), n = SK->GetY()->len(), d = l;
    std::vector<int> wildcard2Pi;
    for(int i = 1; i <= d; i++){
        if(!element_is0(*SK->P->At(i)) && element_is0(*P_new->At(i))){
            throw "P' not approximate P ! ";
        }
        if(element_is0(*SK->P->At(i)) && !element_is0(*P_new->At(i))){
            wildcard2Pi.push_back(i);
        }
    }

    this->y = new ElementList(SK->GetY(), 0);
    this->P = new ElementList(P_new, 0);
    element_t r, t, tmp1, tmp2;
    element_init_same_as(this->r_1_zy,*SK->GetR_1_zy());
    element_set(this->r_1_zy, *SK->GetR_1_zy());
    element_init_same_as(r, *PK->GetC());
    element_init_same_as(t, *PK->GetC());
    element_random(r);
    element_random(t);

    this->a_i = new ElementList(3, 0, *PK->GetG(), false);
    element_set(*this->a_i->At(1), *SK->GetA_i(1)); //a'_1 = a_1
    
    element_init_same_as(tmp1, *PK->GetH_1_line());
    element_init_same_as(tmp2, *PK->GetH_1_line());
    element_set1(tmp2);
    for(auto &i:wildcard2Pi){
        element_pow_zn(tmp1, *SK->b_i->At(i), *P_new->At(i));
        element_mul(*this->a_i->At(1), tmp1, *this->a_i->At(1));    //*b_i^{P_i}
    }
    for(int i = 1; i <= d; i++){
        if(!element_is0(*P_new->At(i))){
            element_pow_zn(tmp1, *param->GetU_i_H_i_C(i), *P_new->At(i));
            element_mul(tmp2, tmp2,tmp1);
        }
    }
    element_pow_zn(tmp2, tmp2,r);
    element_mul(*this->a_i->At(1), tmp2, *this->a_i->At(1));    //a'_1

    element_pow_zn(*this->a_i->At(2), *PK->GetG(), *PK->GetC()); //g^c
    element_div(*this->a_i->At(2), *PK->GetG_1(),*this->a_i->At(2)); //g^{a-c}
    element_pow_zn(*this->a_i->At(3), *this->a_i->At(2), t);
    element_mul(*this->a_i->At(3), *this->a_i->At(3), *SK->a_i->At(3)); //a'_3

    element_pow_zn(*this->a_i->At(2), *this->a_i->At(2), r);
    element_mul(*this->a_i->At(2), *this->a_i->At(2), *SK->a_i->At(2)); //a'_2

    this->b_i = new ElementList(d, 0, *PK->GetG(), false);
    this->c_i = new ElementList(d, 0, *PK->GetG(), false);
    this->d_i = new ElementList(d, 0, *PK->GetG(), false);

    for (int i = 1; i <= d; i++)
    {
        element_pow_zn(*this->b_i->At(i), *param->GetU_i_H_i_C(i), r);
        element_mul(*this->b_i->At(i), *SK->b_i->At(i), *this->b_i->At(i));
        element_pow_zn(*this->c_i->At(i), *param->GetU_i_H_i_C(i), t);
        element_mul(*this->c_i->At(i), *SK->c_i->At(i), *this->c_i->At(i));
            
        if(!element_is0(*P_new->At(i))){
            if(!element_is0(*SK->GetP_i(i))){
            element_pow_zn(*this->d_i->At(i), *param->GetU_i_H_i_C_P_i(i),r);
            element_div(*this->d_i->At(i), *this->c_i->At(i), *this->d_i->At(i));
            element_mul(*this->d_i->At(i), *SK->GetD_i(i) , *this->d_i->At(i));
            }
            else{
                element_pow_zn(*this->d_i->At(i), *param->GetU_i_H_i_C_P_i(i),r);
                element_div(*this->d_i->At(i), *this->c_i->At(i), *this->d_i->At(i));
                element_mul(*this->d_i->At(i), *SK->GetD_i(i), *this->c_i->At(i));

                element_pow_zn(tmp1, *SK->b_i->At(i), *P_new->At(i));
                element_div(*this->d_i->At(i), *this->d_i->At(i), tmp1); 
            }
            element_set0(*this->b_i->At(i));
            element_set0(*this->c_i->At(i));
        }
        else{
            element_set0(*this->d_i->At(i));
        }
    }

    element_clear(r);
    element_clear(t);
    element_clear(tmp1);
    element_clear(tmp2);
};

    element_t *SecretKeyWIB::GetR_1_zy(){
        return &this->r_1_zy;
    };

    ElementList *SecretKeyWIB::GetY(){
        return this->y;
    };

    ElementList *SecretKeyWIB::GetC(){
        return this->c_i;
    };

    element_t *SecretKeyWIB::GetP_i(int i){
        return this->P->At(i);
    };

    element_t *SecretKeyWIB::GetY_i(int i){
        return this->y->At(i);
    };

    element_t *SecretKeyWIB::GetA_i(int i){
        return this->a_i->At(i);
    };

    element_t *SecretKeyWIB::GetB_i(int i){
        return this->b_i->At(i);
    };

    element_t *SecretKeyWIB::GetC_i(int i){
        return this->c_i->At(i);
    };

    element_t *SecretKeyWIB::GetD_i(int i){
        return this->d_i->At(i);
    };

    std::string SecretKeyWIB::toString(){
    int buflen = 1024;
    char buf[buflen];
    std::string res = "SecretKeyWIB类\n", tmp;
    element_snprint(buf, buflen, *this->GetR_1_zy());
    tmp = buf;
    res += "r_1_zy: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetA_i(1));
    tmp = buf;
    res += "a_1: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetA_i(2));
    tmp = buf;
    res += "a_2: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetA_i(3));
    tmp = buf;
    res += "a_3: " + tmp + "\n";
    res += this->y->toString("n", "y");
    res += this->b_i->toString("d", "b_i");
    res += this->c_i->toString("d", "c_i");
    res += this->d_i->toString("d", "d_i");
    return res;
    };

    SecretKeyWIB::~SecretKeyWIB(){
        if(this->P !=NULL) delete this->P;
        if(this->y !=NULL) delete this->y;
        if(this->a_i !=NULL) delete this->a_i;
        if(this->b_i !=NULL) delete this->b_i;
        if(this->c_i !=NULL) delete this->c_i;
        if(this->d_i !=NULL) delete this->d_i;
        element_clear(this->r_1_zy);
    };

//TODO: IBBE
SecretKeyIBBE::SecretKeyIBBE(PublicKeyIBBE *PK, MasterKeyIBBE *MSK, element_t ID, ElementList *y){
    this->y = new ElementList(y, 0);
    int n = y->len();
    element_init_same_as(this->ID, *MSK->GetAlpha());
    element_set(this->ID, ID);
    element_init_same_as(this->K_1, *PK->GetG());
    element_init_same_as(this->K_2, *MSK->GetAlpha());
    
    element_random(this->K_2);    //K_2 = k

    element_t res1,res2, tmp;
    element_init_same_as(res1, this->K_2);
    element_init_same_as(res2, this->K_2);
    element_init_same_as(tmp, *MSK->GetAlpha());
    element_set0(res1);
    element_set(tmp, *MSK->GetAlpha());
    for (int i = 1; i <= n; i++)
    {
        element_mul(res2, *MSK->GetBeta_i(i), *y->At(i));
        element_add(res1, res1, res2);
    }   // res1 = <beta,y>
    element_pow_zn(this->K_1, *PK->GetG(), res1);
    element_div(this->K_1, this->K_1, this->K_2);   //g^{<beta, y> - k}
    element_pow_zn(this->K_1, this->K_2, *MSK->GetN_1());
    element_sub(tmp, tmp, ID);  //(a-H(ID))
    element_pow_zn(this->K_1, this->K_1, tmp);

    element_clear(tmp);
    element_clear(res2);
    element_clear(res1);
};

element_t *SecretKeyIBBE::GetK_1(){
    return &this->K_1;
};

element_t *SecretKeyIBBE::GetK_2(){
    return &this->K_2;
};

element_t *SecretKeyIBBE::GetID(){
    return &this->ID;
};

ElementList *SecretKeyIBBE::GetY(){
    return this->y;
};

std::string SecretKeyIBBE::toString(){
    int buflen = 1024;
    char buf[buflen];
    std::string res = "SecretKeyIBBE类\n", tmp;
    element_snprint(buf, buflen, *this->GetK_1());
    tmp = buf;
    res += "K_1: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetK_2());
    tmp = buf;
    res += "K_2: " + tmp + "\n";
    res += this->y->toString("n", "y");
    return res;
};

SecretKeyIBBE::~SecretKeyIBBE(){
    if(this->y != NULL) delete this->y;
    this->y = NULL;
    element_clear(this->ID);
    element_clear(this->K_1);
    element_clear(this->K_2);
};

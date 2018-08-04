
#include "dh.h"

int get_n(char* a)
{
    int i = MAX - 1;
    while(i >= 0 && !a[i] ) i--;
    return i + 1;
}

int get_mul(char* a,char* b)
{
    int na, nb, i, j, n;
    char c[MAX], d[MAX];
    for(i = 0; i < MAX; i++) c[i] = a[i], d[i] = b[i], a[i]=0;
    na = get_n(c);
    nb = get_n(d);
    for(i = 0; i < nb; i++) for(j = 0; j < na; j++)
    {
            a[i+j] += d[i] * c[j];
            if(a[i + j] > 9) a[i + 1 + j] += a[i + j] / 10, a[i + j] %= 10;
    }
    for(i = 0; i < MAX && i< (na + nb); i++)
    {
        if(a[i]) n = i + 1;
        if(a[i] > 9) a[i + 1] += a[i] / 10, a[i] %= 10;
    }
    return n;
}

int get_mod(char* a,char* b)
{
    int na, nb, i, u, f = 0, n;
    na = get_n(a);
    nb = get_n(b);
    u = na - nb;
    if(u < 0) return 0;
    while(u + 1)
    {
        for(i = na - 1,f = 0; i >= u; i--)
        {
            if(a[i] > b[i - u])
            {
                f = 1;
                break;
            }
            if(a[i] < b[i - u])
            {
                f = -1;
                break;
            }
        }
        if(!f)
        {
            for(i = na - 1; i >= u; i--) a[i] = 0;
            u -= nb;
            if(u < 0) break;
            continue;
        }
        if(f == -1) u--;
        if(f == 1)
        {
            for(i = u; i < na; i++)
            {
                a[i] -= b[i - u];
                if(a[i]<0) a[i + 1]--, a[i] += 10;
            }
        }
    }
    for(i = 0; i < na; i++) if(a[i]) n = i + 1;

    return n;
}

void reverse(char* a)
{
    int i, n;
    n = get_n(a);
    for(i = 0; i < n/2; i++) swap(a[i], a[n - 1 - i]);
}

void get_a(char* a)
{
    int i = 0;
    while(a[i]) a[i++] -= '0';
}

void get_g(char* a)
{
    int i, r, j = 0;;
    srand(time(0));
    while(1)
    {
        r = rand()%10000;
        for(i = 0; i < 4; i++)
        {
            a[j++] = r%10;
            r /= 10;
            if(j == NUMG) return;
        }
    }
}

void get_p(char* a, int n)
{
    int i;
    for(i = 0; i < 100; i++) a[i] = p_set[n][i];
}

void display(char* a)
{
    int n, i;
    n = get_n(a);
    reverse(a);
    for(i = 0; i < n; i++) printf("%d", a[i]);
    printf("\n");
    reverse(a);
}

void sent(int a, char* p, char* g, char *ans)
{
    char t[MAX] = {0};
    int p_n = 0;
    int i;
    memset(p, 0, MAX * sizeof(p[0]));
    memset(g, 0, MAX * sizeof(g[0]));
    srand(time(0));
    p_n = rand()%NUMP;   //随机得到p_n
    get_g(g);
    get_p(p, p_n);
    get_a(p);
    reverse(p);
    for(i = 0; i < MAX; i++) t[i] = g[i], ans[i] = 0;
    ans[0] = 1;
    for(i = 0; i < 32; i++)
    {
        if(a&1 << i)
        {
            get_mul(ans, t);
            get_mod(ans, p);
        }
        get_mul(t, t);
        get_mod(t, p);
    }
}

void rec(int b, char *p, char *g, char *ans)
{
    char t[MAX] = {0};
    int i;
    for(i = 0; i < MAX; i++) t[i] = g[i], ans[i] = 0;
    ans[0] = 1;
    for(i = 0; i < 32; i++)
    {
        if(b&1 << i)
        {
            get_mul(ans, t);
            get_mod(ans, p);
        }
        get_mul(t, t);
        get_mod(t, p);
    }
}

void get_key(int b, char *rec, char*p, char*g, char *ans)
{
    char t[MAX] = {0};
    int i;

    for(i = 0; i < MAX; i++) t[i] = rec[i], ans[i] = 0;
    ans[0] = 1;
    for(i = 0; i < 32; i++)
    {
        if(b&1 << i)
        {
            get_mul(ans, t);
            get_mod(ans, p);
        }
        get_mul(t, t);
        get_mod(t, p);
    }
}

/*
void main()      //用单机模拟双机的密钥交换过程
{
    char sa[MAX],sb[MAX],p[MAX],g[MAX],ak[MAX],bk[MAX];
    int a,b;
    printf("A选择的随机数：");
    scanf("%d",&a);
    printf("B选择的随机数：");
    scanf("%d",&b);
    sent(a,p,g,sa);   //A将sa=p^a get_mod g和p，g的值发送给B，
    rec(b,p,g,sb);   //B收到后用收到的p,g计算出sb=p^b get_mod g，并将结果返回给A
    get_key(a,sb,p,g,ak);   //A得到的密钥为ak=sb^a get_mod g
    get_key(b,sa,p,g,bk);   //B得到的密钥为bk=sa^a get_mod g

    //输出A得到的密钥ak，和B得到的密钥bk,根据取模的性质，ak==bk
    printf("A得到的密钥为：\n");
    display(ak);
    printf("\n");
    printf("B得到的密钥为：\n");
    display(bk);
    printf("\n");
}*/

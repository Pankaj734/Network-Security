#include<iostream>
#include<stdlib.h>
#include<algorithm>
#include<time.h>
#include<math.h>
#define N 256 //bytes
#define K 2048 //bits
#define OP 32 //bytes

using namespace std;

void swap(int *a, int *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

void CopyArray(int *s, int *d)
{
  for(int i=0; i<K; i++){
    d[i] = s[i];
  }
}

//Utility for Prrinting Array
void PrintArray(int *a, int n){
  for(int i=0; i<n; i++){
    cout<<a[i]<<" ";
  }
  cout<<endl;
}
void PrintArray(double *a, int n){
  for(int i=0; i<n; i++){
    cout<<a[i]<<" ";
  }
  cout<<endl;
}

double Var(int *arr, int n){
  int sum = 0;
  for(int i=0; i<n; i++) sum += arr[i];

  double mean = (double)sum/(double)n ;

  double sqdiff = 0;
  for(int i=0; i<n; i++){
    sqdiff += (arr[i]-mean)*(arr[i]-mean);
  }

  return sqdiff/n;
}

double StdDev(int *arr, int n){
  return sqrt(Var(arr,n));
}

void Toggle(int *Key, int *NewKey, int nb){
  int i=0;
  int bits = nb;

  CopyArray(Key, NewKey);

  while(bits--){
    NewKey[i] = 1 - NewKey[rand()%2048];
    i++;
  }
}

void KSA(int *key,int *S)
{
  int j=0;
  for(int i=0; i<N; i++){
    S[i] = i;
  }

  for(int i=0; i<N; i++){
    j = (j + S[i] + key[i]) % N;
    swap(&S[i], &S[j]);
  }
}

void PRGA(int *S, int *KS)
{
  int i=0,j=0;
  int n = OP*8;
  //Assuming plaintext length as N
  for(int k=0; k<n; k++){
    i = (i+1)%N;
    j = (j+S[i])%N;

    swap(&S[i], &S[j]);
    int t = (S[i]+S[j])%N;

    KS[k] = S[t]%2;
  }
}

int main()
{
  int key[K];
  srand(time(0));
  for(int i=0; i<K; i++){
    key[i] = rand()%2;
  }

  int S[N],KeyStream[OP*8];

  KSA(key, S);
  PRGA(S, KeyStream);

  int NewKey[K];
  int NewKS[OP*8];

  double std_dev[32];
  int counter[256];
    for(int i=1; i<=32; i++){
      for(int k=0; k<256; k++){
        counter[k]=0;
      }
      for(int sample=1; sample<=200; sample++)
      {
        Toggle(key,NewKey,i);
        KSA(NewKey, S);
        PRGA(S, NewKS);

        int diff[OP*8] = {0};
        for(int k=0; k<OP*8; k++){
          diff[k] = KeyStream[k]^NewKS[k];
        }

        for(int k=0; k<OP*8; k+=8){
          int p = 0;
          int num = 0;
          for(int j=k+7; j>=k; j--){
            num += diff[j]*pow(2,p);
            p++;
          }
          counter[num]++;
        }
      }

      std_dev[i-1] = StdDev(counter,256);
    }

  double Randomness[32];
  for(int i=0; i<32; i++){
    Randomness[i] = (std_dev[i]*((double)256))/((double)(OP*8 - 7)) ;
  }

  cout<<"--------Randomness Values for output Length = "<<OP<<" ---------"<<endl;
  for(int i=0; i<32; i++){
    cout<<Randomness[i]<<endl;
  }

  return 0;
}

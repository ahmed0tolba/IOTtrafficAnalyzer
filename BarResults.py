import numpy as np
import matplotlib.pyplot as plt
   
KNN = [97,100,99.93,100,97,99,100]
SVM = [80,100,100,100,97,100,100]
RF = [99.97,100,100,99.93,100,100,100]
ANN = [90,100,100,100,100,99.48,100]
CNN = [94,100,100,100,100,99.72,100]
Autoencoders = [95,100,100,100,98,98,99]
XGB_boost = [99.93,100,100,100,100,99,100]
XGB_skilearn = [99.93,100,100,100,100,100,100]
ensemble = [100,100,100,100,100,100,100]
  
n=7
r = np.arange(n)
width = 0.08
  
  
bar1 = plt.bar(r, KNN, color = 'lightcoral',width = width, edgecolor = 'black',label='KNN')
bar2 = plt.bar(r + width, SVM, color = 'darkorange',width = width, edgecolor = 'black',label='SVM')
bar3 = plt.bar(r + 2 * width, RF, color = 'chocolate',width = width, edgecolor = 'black',label='RF')
bar4 = plt.bar(r + 3 * width, RF, color = 'gold',width = width, edgecolor = 'black',label='ANN')
bar5 = plt.bar(r + 4 * width, RF, color = 'yellowgreen',width = width, edgecolor = 'black',label='CNN')
bar6 = plt.bar(r + 5 * width, RF, color = 'turquoise',width = width, edgecolor = 'black',label='Autoencoders')
bar7 = plt.bar(r + 6 * width, RF, color = 'deepskyblue',width = width, edgecolor = 'black',label='XGB boost')
bar8 = plt.bar(r + 7 * width, RF, color = 'blueviolet',width = width, edgecolor = 'black',label='XGB skilearn')
bar9 = plt.bar(r + 8 * width, RF, color = 'hotpink',width = width, edgecolor = 'black',label='ensemble')

  
plt.xlabel("Traffic type")
plt.ylabel("Accuracy %")
plt.title("Traffic identifcation accuracy by each ML model %")

for rect in bar1 + bar2 + bar3 + bar4 + bar5 + bar6 + bar7 + bar8 + bar9 :
    height = rect.get_height()
    plt.text(rect.get_x() + rect.get_width() / 2.0, height+1, f'{height:.0f}', ha='center', va='bottom',rotation='vertical',fontsize=8)

# plt.grid(linestyle='--')
plt.xticks(r + width/2 + .3,['Normal','MITM','UDP DOS','Password','Deauth','Syn DOS','Nmap'])
plt.legend()
plt.xlim(xmax = 7 + width/2 + 1)
plt.show()
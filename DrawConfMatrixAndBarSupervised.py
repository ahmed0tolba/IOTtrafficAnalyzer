import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sn
import matplotlib

confussion_matrix_labels = ['Normal','MITM','UDP','Password','Deauth','DOS','Scan']
colors = ["#FFFFFF", "#FFFFFF"]
cmap = matplotlib.colors.LinearSegmentedColormap.from_list("", colors)

KNN = [99,100,100,100,98,99,100]
SVM = [80,100,100,100,97,100,100]
RF = [99.97,100,100,99.93,100,100,100]
ANN = [90,100,100,100,100,99.48,100]
CNN = [94,100,100,100,100,99.72,100]
Autoencoders = [95,100,100,100,98,98,99]
XGB_boost = [99.93,100,100,100,100,99,100]
XGB_skilearn = [99.93,100,100,100,100,100,100]
ensemble = [100,100,100,100,100,100,100]

KNN_confusion_matrix=[[99,0.21,0,0,0.84,0,0],[0,100,0,0,0,0,0],[0.07,0,100,0,0,0,0.07],[0,0,0,100,0,0,0],[1.3,0.07,0,0,98,0.35,0],[0.07,0,0,0.28,0.77,99,0],[0,0,0,0,0,0,100]]
SVM_confusion_matrix=[[80,0,0,0,20,0,0],[0,100,0,0,0,0,0],[0,0,100,0,0,0,0],[0,0,0,100,0,0,0],[0,0,0,0,100,0,0],[0,0,0,0,2.7,97.3,0],[0,0,0,0,0,0,100]]
RF_confusion_matrix=[[99.97,0,0,0,0.07,0,0],[0,100,0,0,0,0,0],[0,0,100,0,0,0,0],[0,0,0,100,0,0,0],[0,0,0,0,100,0,0],[0,0,0,0,0,100,0],[0,0,0,0,0,0,100]]
ANN_confusion_matrix=[[90,0.35,0,0,8.7,0.42,0],[0,100,0,0,0,0,0],[0,0,100,0,0,0,0],[0,0,0,100,0,0,0],[0,0,0,0,100,0,0],[0.28,0,0,0,0.07,100,0.07],[0,0,0,0,0,0,100]]
CNN_confusion_matrix=[[94,0,0,0,5.4,0.84,0.07],[0,100,0,0,0,0,0],[0,0,100,0,0,0,0],[0,0,0,100,0,0,0],[0,0,0,0,100,0,0],[0,0,0,0,0.21,100,0.07],[0,0,0,0,0,0,100]]
Auto_confusion_matrix=[[95,0.14,0,0,5,0.35,0],[0,100,0,0,0,0,0],[0,0,100,0,0,0,0],[0,0,0,100,0,0,0],[0,0,0,0,100,0,0],[0,0,0,0,0.84,99,0.21],[0,0,0,0,0,0,100]]
XGBb_confusion_matrix=[[99.93,0,0,0,0,0,0.07],[0,100,0,0,0,0,0],[0,0,100,0,0,0,0],[0,0,0,100,0,0,0],[0,0,0,0,100,0,0],[0,0,0,0,0,100,0],[0,0,0,0,0,0,100]]
XGBs_confusion_matrix=[[99.93,0,0,0,0,0,0.07],[0,100,0,0,0,0,0],[0,0,100,0,0,0,0],[0,0,0,100,0,0,0],[0,0,0,0,100,0,0],[0,0,0,0,0,100,0],[0,0,0,0,0,0,100]]
ens_confusion_matrix=[[100,0,0,0,0,0,0],[0,100,0,0,0,0,0],[0,0,100,0,0,0,0],[0,0,0,100,0,0,0],[0,0,0,0,100,0,0],[0,0,0,0,0,100,0],[0,0,0,0,0,0,100]]



n=7
r = np.arange(n)
width = 0.08
  
  
bar1 = plt.bar(r, KNN, color = 'lightcoral',width = width, edgecolor = 'black',label='KNN')
bar2 = plt.bar(r + width, SVM, color = 'darkorange',width = width, edgecolor = 'black',label='SVM')
bar3 = plt.bar(r + 2 * width, RF, color = 'chocolate',width = width, edgecolor = 'black',label='RF')
bar4 = plt.bar(r + 3 * width, ANN, color = 'gold',width = width, edgecolor = 'black',label='ANN')
bar5 = plt.bar(r + 4 * width, CNN, color = 'yellowgreen',width = width, edgecolor = 'black',label='CNN')
bar6 = plt.bar(r + 5 * width, Autoencoders, color = 'turquoise',width = width, edgecolor = 'black',label='Autoencoders')
bar7 = plt.bar(r + 6 * width, XGB_boost, color = 'deepskyblue',width = width, edgecolor = 'black',label='XGB boost')
bar8 = plt.bar(r + 7 * width, XGB_skilearn, color = 'blueviolet',width = width, edgecolor = 'black',label='XGB skilearn')
bar9 = plt.bar(r + 8 * width, ensemble, color = 'hotpink',width = width, edgecolor = 'black',label='ensemble')

plt.xlabel("Traffic type")
plt.ylabel("Accuracy %")
plt.title("Traffic identifcation accuracy by each ML model %")

for rect in bar1 + bar2 + bar3 + bar4 + bar5 + bar6 + bar7 + bar8 + bar9 :
    height = rect.get_height()
    plt.text(rect.get_x() + rect.get_width() / 2.0, height+1, f'{height:.0f}', ha='center', va='bottom',rotation='vertical',fontsize=8)

plt.xticks(r + width/2 + .3,['Normal','MITM','UDP DOS','Password','Deauth','Syn DOS','Nmap'])
plt.legend()
plt.xlim(xmax = 7 + width/2 + 1)
plt.show()

# exit()

result = pd.DataFrame(KNN_confusion_matrix,confussion_matrix_labels,confussion_matrix_labels)
result.to_csv('KNN_confusion_matrix.csv')
ax = sn.heatmap(result, annot=True, annot_kws={"size": 12},xticklabels = True,cbar=False,square=True,cmap=cmap,linecolor="#000000",linewidths=1) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("KNN Confusion Matrix")
plt.show()

# exit()

result = pd.DataFrame(RF_confusion_matrix,confussion_matrix_labels,confussion_matrix_labels)
result.to_csv('RF Confusion Matrix.csv')
ax = sn.heatmap(result, annot=True, annot_kws={"size": 12},xticklabels = True,cbar=False,square=True,cmap=cmap,linecolor="#000000",linewidths=1) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("RF Confusion Matrix")
plt.show()


df_confusion_matrix_XGB = pd.DataFrame(XGBb_confusion_matrix,confussion_matrix_labels,confussion_matrix_labels)
df_confusion_matrix_XGB.to_csv('XGB boost Confusion Matrix.csv')
ax = sn.heatmap(df_confusion_matrix_XGB, annot=True, annot_kws={"size": 12},xticklabels = True,cbar=False,square=True,cmap=cmap,linecolor="#000000",linewidths=1) # font size
ax.set(xlabel="Actual Values", ylabel="Predicted Values")
ax.xaxis.tick_top()
ax.set_title("XGB boost Confusion Matrix")
plt.show()

result = pd.DataFrame(XGBs_confusion_matrix,confussion_matrix_labels,confussion_matrix_labels)
result.to_csv('XGB skilearn Confusion Matrix.csv')
ax = sn.heatmap(result, annot=True, annot_kws={"size": 12},xticklabels = True,cbar=False,square=True,cmap=cmap,linecolor="#000000",linewidths=1) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("XGB skilearn Confusion Matrix")
plt.show()

result = pd.DataFrame(SVM_confusion_matrix,confussion_matrix_labels,confussion_matrix_labels)
result.to_csv('SVM_confusion_matrix.csv')
ax = sn.heatmap(result, annot=True, annot_kws={"size": 12},xticklabels = True,cbar=False,square=True,cmap=cmap,linecolor="#000000",linewidths=1) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("SVM Confusion Matrix")
plt.show()

result = pd.DataFrame(Auto_confusion_matrix,confussion_matrix_labels,confussion_matrix_labels)
result.to_csv('autoencoder Confusion Matrix.csv')
ax = sn.heatmap(result, annot=True, annot_kws={"size": 12},xticklabels = True,cbar=False,square=True,cmap=cmap,linecolor="#000000",linewidths=1) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("autoencoder Confusion Matrix")
plt.show()

result = pd.DataFrame(ANN_confusion_matrix,confussion_matrix_labels,confussion_matrix_labels)
result.to_csv('ANN_confusion_matrix.csv')
ax = sn.heatmap(result, annot=True, annot_kws={"size": 12},xticklabels = True,cbar=False,square=True,cmap=cmap,linecolor="#000000",linewidths=1) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("ANN Confusion Matrix")
plt.show()

result = pd.DataFrame(CNN_confusion_matrix,confussion_matrix_labels,confussion_matrix_labels)
result.to_csv('CNN_confusion_matrix.csv')
ax = sn.heatmap(result, annot=True, annot_kws={"size": 12},xticklabels = True,cbar=False,square=True,cmap=cmap,linecolor="#000000",linewidths=1) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("CNN Confusion Matrix")
plt.show()

result1 = pd.DataFrame(ens_confusion_matrix,confussion_matrix_labels,confussion_matrix_labels)
result.to_csv('ensemble Confusion Matrix.csv')
ax = sn.heatmap(result1, annot=True, annot_kws={"size": 12},xticklabels = True,cbar=False,square=True,cmap=cmap,linecolor="#000000",linewidths=1) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("ensemble Confusion Matrix")
plt.show()



# plt.grid(linestyle='--')

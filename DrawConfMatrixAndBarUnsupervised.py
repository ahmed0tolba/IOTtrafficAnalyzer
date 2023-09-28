import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sn
import matplotlib

confussion_matrix_labels = ['Benign','Malignant']
colors = ["#FFFFFF", "#FFFFFF"]
cmap = matplotlib.colors.LinearSegmentedColormap.from_list("", colors)

good_size = 148
mal_size = 12627
Isolation_Forest = [round(98/good_size*100),round(12620/mal_size*100)]
One_Class_SVM = [round(118/good_size*100),round(12627/mal_size*100)]
Elliptic_Envelope = [round(103/good_size*100),round(11341/mal_size*100)]
Local_Outlier_Factor = [round(128/good_size*100),round(11598/mal_size*100)]

Isolation_Forest_matrix=[[round(98/good_size*100),round((good_size-98)/good_size*100)],[round((mal_size-12620)/mal_size*100),round(12620/mal_size*100)]]
One_Class_SVM_matrix=[[round(118/good_size*100),round((good_size-118)/good_size*100)],[round((mal_size-12627)/mal_size*100),round(12627/mal_size*100)]]
Elliptic_Envelope_matrix=[[round(103/good_size*100),round((good_size-103)/good_size*100)],[round((mal_size-11341)/mal_size*100),round(11341/mal_size*100)]]
Local_Outlier_Factor_matrix=[[round(128/good_size*100),round((good_size-128)/good_size*100)],[round((mal_size-11598)/mal_size*100),round(11598/mal_size*100)]]

n=2
r = np.arange(n)
width = 0.2
  
bar1 = plt.bar(r, Isolation_Forest, color = 'lightcoral',width = width, edgecolor = 'black',label='Isolation Forest')
bar2 = plt.bar(r + width, One_Class_SVM, color = 'darkorange',width = width, edgecolor = 'black',label='One Class SVM')
bar3 = plt.bar(r + 2 * width, Elliptic_Envelope, color = 'chocolate',width = width, edgecolor = 'black',label='Elliptic Envelope')
bar4 = plt.bar(r + 3 * width, Local_Outlier_Factor, color = 'gold',width = width, edgecolor = 'black',label='The Local Outlier Factor')

plt.xlabel("Traffic type")
plt.ylabel("Accuracy %")
plt.title("Traffic Anomaly delection accuracy by each ML model %")

for rect in bar1 + bar2 + bar3 + bar4:
    height = rect.get_height()
    plt.text(rect.get_x() + rect.get_width() / 2.0, height+1, f'{height:.0f}', ha='center', va='bottom',rotation='vertical',fontsize=8)

# plt.grid(linestyle='--')
plt.xticks(r + width/2 + .2,['Benign','Malignant'])
plt.legend()
plt.xlim(xmax = 2 + width/2 + 1)
plt.ylim(ymax = 110 )
plt.show()

# exit()

result = pd.DataFrame(Isolation_Forest_matrix,confussion_matrix_labels,confussion_matrix_labels)
result.to_csv('Isolation_Forest_matrix.csv')
ax = sn.heatmap(result, annot=True, annot_kws={"size": 12},xticklabels = True,cbar=False,square=True,cmap=cmap,linecolor="#000000",linewidths=1) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("Isolation Forest matrix")
plt.show()



result = pd.DataFrame(One_Class_SVM_matrix,confussion_matrix_labels,confussion_matrix_labels)
result.to_csv('One Class SVM matrix.csv')
ax = sn.heatmap(result, annot=True, annot_kws={"size": 12},xticklabels = True,cbar=False,square=True,cmap=cmap,linecolor="#000000",linewidths=1) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("One Class SVM matrix")
plt.show()


df_confusion_matrix_XGB = pd.DataFrame(Elliptic_Envelope_matrix,confussion_matrix_labels,confussion_matrix_labels)
df_confusion_matrix_XGB.to_csv('Elliptic Envelope matrix.csv')
ax = sn.heatmap(df_confusion_matrix_XGB, annot=True, annot_kws={"size": 12},xticklabels = True,cbar=False,square=True,cmap=cmap,linecolor="#000000",linewidths=1) # font size
ax.set(xlabel="Actual Values", ylabel="Predicted Values")
ax.xaxis.tick_top()
ax.set_title("Elliptic Envelope matrix")
plt.show()

result = pd.DataFrame(Local_Outlier_Factor_matrix,confussion_matrix_labels,confussion_matrix_labels)
result.to_csv('Local Outlier Factor matrix.csv')
ax = sn.heatmap(result, annot=True, annot_kws={"size": 12},xticklabels = True,cbar=False,square=True,cmap=cmap,linecolor="#000000",linewidths=1) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("Local Outlier Factor matrix")
plt.show()


import pandas as pd 
import numpy as np
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.model_selection import ParameterGrid
from sklearn.cluster import KMeans
from sklearn import metrics
from sklearn.preprocessing import LabelEncoder

df = pd.read_csv('uploadedFiles/Joined In depth packet analysis.csv')
df.fillna(0, inplace=True)
print(type(df))
print(df.head(5))

print('The shape of our features is:', df.shape)

# Descriptive statistics for each column
print(df.describe())

le_Protocol = LabelEncoder()
label_Protocol = le_Protocol.fit_transform(df['Protocol'])
df.drop("Protocol", axis=1, inplace=True)
df["Protocol"] = label_Protocol

# le_attack_type = LabelEncoder()
# label_attack_type = le_attack_type.fit_transform(df['attack type'])
# df.drop("attack type", axis=1, inplace=True)
# df["attack type"] = label_attack_type

le_isserver = LabelEncoder()
label_isserver = le_isserver.fit_transform(df['IsServer'])
df.drop("IsServer", axis=1, inplace=True)
df["IsServer"] = label_isserver

df['attack'].replace(0, 'Benign',inplace=True)
df['attack'].replace(1, 'Malignant',inplace=True)

# df_important= df.loc[: , ["Protocol","No_of_received_packets_per_minutes","No_of_sent_packets_per_minutes","Flow_volume","IsServer","attack"]]
df_important= df.loc[: , ["Protocol","No_of_received_packets_per_minutes","No_of_sent_packets_per_minutes","Flow_volume","IsServer","attack type"]]

x = df_important.loc[:, ["Protocol","No_of_received_packets_per_minutes","No_of_sent_packets_per_minutes","Flow_volume","IsServer"]].values
y = df_important.loc[:,['attack type']].values

x= StandardScaler().fit_transform(x)
pca = PCA(n_components=2)
principalComponents = pca.fit_transform(x)

principalDf = pd.DataFrame(data = principalComponents, columns = ['principal component 1', 'principal component 2'])

finalDf = pd.concat([principalDf, df[['attack type']]], axis = 1)

# plt.figure()
# plt.figure(figsize=(10,10))
# plt.xticks(fontsize=12)
# plt.yticks(fontsize=14)
# plt.xlabel('Principal Component - 1',fontsize=20)
# plt.ylabel('Principal Component - 2',fontsize=20)
# plt.title("",fontsize=20)
# targets = ['Benign', 'Malignant']
# colors = ['r', 'g']
# for target, color in zip(targets,colors):
#     indicesToKeep = df_important['attack'] == target
#     plt.scatter(principalDf.loc[indicesToKeep, 'principal component 1']
#                , principalDf.loc[indicesToKeep, 'principal component 2'], c = color, s = 20)

# plt.legend(targets,prop={'size': 15})
# plt.show()


pca_3 = PCA(n_components=3)
principalComponents = pca_3.fit_transform(x)
principalDf = pd.DataFrame(data = principalComponents, columns = ['principal component 1', 'principal component 2', 'principal component 3'])
finalDf = pd.concat([principalDf, df[['attack type']]], axis = 1)


optimum_num_clusters = 6
kmeans = KMeans(n_clusters=optimum_num_clusters)
kmeans.fit(x)
centroids = kmeans.cluster_centers_
centroids_pca = pca_3.transform(centroids)

# X = principalDf[:, 0]
# Y = principalDf[:, 1]
# Z = principalDf[:, 2]

fig = plt.figure()
ax = fig.add_subplot(projection='3d')
ax.scatter(centroids_pca[:, 0], centroids_pca[:, 1], centroids_pca[:, 2], marker='X', s=100, linewidths=1.5, alpha=.2,
            color='red', edgecolors="black",zorder=-1)
colors = ["g","r","b","y","c","k"]
labels = ['0', 'deauth','MITM','dos','scan','UDP flood muliport']
# labels = ["class 1", "Class 2"]
# targets = ['Benign', 'Malignant']
targets = ['0', 'deauth','MITM','dos','scan','UDP flood muliport']
for target, color in zip(targets,colors):
    indicesToKeep = df_important['attack type'] == target
    ax.scatter(principalDf.loc[indicesToKeep, 'principal component 1'], principalDf.loc[indicesToKeep, 'principal component 2'], principalDf.loc[indicesToKeep, 'principal component 3'],c=color, alpha=0.8, s=20,zorder=1)



ax.set_xlabel('PCA 1')
ax.set_ylabel('PCA 2')
ax.set_zlabel('PCA 3')

plt.show()
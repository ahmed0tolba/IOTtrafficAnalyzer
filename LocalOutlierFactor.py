import numpy as np
from sklearn.neighbors import LocalOutlierFactor
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import ADASYN, SMOTE # pip install imbalanced-learn
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt

df = pd.read_csv('multi/_Joined In depth packet analysis.csv')
le_Protocol = LabelEncoder()
label_Protocol = le_Protocol.fit_transform(df['Protocol'])
df.drop("Protocol", axis=1, inplace=True)
df["Protocol"] = label_Protocol

le_attack_type = LabelEncoder()
label_attack_type = le_attack_type.fit_transform(df['attack type'])
df.drop("attack type", axis=1, inplace=True)
df["attack type"] = label_attack_type

le_isserver = LabelEncoder()
label_isserver = le_isserver.fit_transform(df['IsServer'])
df.drop("IsServer", axis=1, inplace=True)
df["IsServer"] = label_isserver

attack_labels = np.array(df.loc[: , "attack"])
attack_type_labels = np.array(df.loc[: , "attack type"])

df_x= df.loc[: , ["Protocol","No_of_received_packets_per_minutes","No_of_sent_packets_per_minutes","Flow_volume","IsServer","IOT_Respond_401"]]

# Saving feature names for later use
feature_list = list(df_x.columns)
# print(feature_list)
# Convert to numpy array
numpy_array = np.array(df_x)
# print(numpy_array)


# sm = SMOTE(k_neighbors=2)
# numpy_array_over, attack_type_labels_over = sm.fit_resample(numpy_array, attack_type_labels)

# train_features, test_features, train_labels, test_labels = train_test_split(numpy_array, attack_type_labels, test_size = 0.25, stratify = attack_type_labels)
# train_features_over, test_features_over, train_labels_over, test_labels_over = train_test_split(numpy_array_over, attack_type_labels_over, test_size = 0.25, stratify = attack_type_labels_over)


clf = LocalOutlierFactor(n_neighbors=4)

y = clf.fit_predict(numpy_array)
# print(y)
# print(len(y))
# print(len(clf.negative_outlier_factor_))
# print(clf.negative_outlier_factor_)
# print(type(clf.negative_outlier_factor_))

attack_type_labels_with_negative_outlier_factor = df[['attack type']]
# print(type(attack_type_labels_with_negative_outlier_factor))
# print(type(df))
# print(attack_type_labels_with_negative_outlier_factor.head(5))
attack_type_labels_with_negative_outlier_factor['negative_outlier_factor'] = clf.negative_outlier_factor_.tolist()

corr = attack_type_labels_with_negative_outlier_factor['attack type'].corr(attack_type_labels_with_negative_outlier_factor['negative_outlier_factor'])
print ("Correlation between", 'attack type', "and", 'negative_outlier_factor', "is:", round(corr, 2))

print('Output classes : ',le_attack_type.classes_)

ax = attack_type_labels_with_negative_outlier_factor.plot(x="attack type", y="negative_outlier_factor",kind="scatter",  figsize=(9, 8))
names_list = ['','Normal','MITM','UDP flood','password','deauth','dos','scan']
ax.set_xticklabels(names_list)
plt.show()


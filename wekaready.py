import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Read in data and display first 5 rows
df = pd.read_csv('uploadedFiles/Joined In depth packet analysis.csv')
df.fillna(0, inplace=True)
# print(type(df))
# print(df.head(5))

le_attack_type = LabelEncoder()
label_attack_type = le_attack_type.fit_transform(df['attack type'])
df.drop("attack type", axis=1, inplace=True)
df["attack type"] = label_attack_type

df.to_csv('uploadedFiles/Joined In depth packet analysis_weka.csv', index=False)
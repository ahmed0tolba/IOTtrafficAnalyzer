import os
import pandas
directory = 'uploadedFiles/'
save_joined_file_name = "Joined In depth packet analysis.csv"
joined_df = pandas.DataFrame()
for filename in os.listdir(directory):
    if filename[-36:] == ".pcapng-In depth packet analysis.csv":
        full_path = os.path.join(directory, filename)
        data = pandas.read_csv(full_path)
        joined_df = joined_df.append(data,ignore_index=True)
        print(full_path)

joined_df.to_csv(directory+save_joined_file_name,index=False)


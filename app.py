import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px
from streamlit_option_menu import option_menu
from sklearn.preprocessing import MinMaxScaler
import pickle
import joblib


st.set_page_config(page_title="CVE security vulner",page_icon=":bar_chart:",layout="wide")
st.title(' :bar_chart: CVE security vulnerability database.')
st.markdown(" <style> div.block-container{padding-top:1rem;} </style> ",unsafe_allow_html=True)

selected = option_menu(
     menu_title = None,
     options=['Home','Predict'],
     icons=['house','book'],
     orientation='horizontal',
     default_index=0
)


     #    HOME PAGE     #

if selected=='Home':
     st.title('Home EDA Page')

     # DATA Preparation
     df = pd.read_csv('final_data.csv')
     df['Publish Date'] = pd.to_datetime(df['Publish Date'])
     df['Year'] = df['Publish Date'].dt.year

     startDate = pd.to_datetime(df['Publish Date']).min()
     endDate = pd.to_datetime(df['Publish Date']).max()
     # st.write('Start date : ',startDate.strftime("%Y-%m-%d"))
     # st.write('End date',str(endDate).split(' ')[0])

     col1 , col2 = st.columns((2))
     with col1:
          date1 = pd.to_datetime(st.date_input('Start date : ',startDate))
     with col2:
          date2 = pd.to_datetime(st.date_input('End date : ',endDate))

     df1 = df[ (df['Publish Date'] >= date1) & (df['Publish Date'] <= date2 ) ].copy()


     st.sidebar.header('Filter By :')

     # FILTERS
     vulne_type = st.sidebar.multiselect('Select Vulnerability Type',df['Vulnerability Type(s)'].unique())
     if not vulne_type:
          df2 = df1.copy()
     else:
          df2 = df1[df1['Vulnerability Type(s)'].isin(vulne_type)]

     cwe_id = st.sidebar.multiselect('Select CWE ID',df2['CWE ID'].unique())
     if not cwe_id:
          df3 = df2.copy()
     else:
          df3 = df2[df2['CWE ID'].isin(cwe_id)]

     score = st.sidebar.multiselect('Select Score',sorted(df2['Score'].unique()))
     if not score:
          df4 = df3.copy()
     else:
          df4 = df3[df2['Score'].isin(score)]


     if not vulne_type and not cwe_id and not score:
          df5 = df4.copy()

     elif not vulne_type and not cwe_id:
          df5 = df4[df4['Score'].isin(score)]
     elif not vulne_type and not score:
          df5 = df4[df4['CWE ID'].isin(cwe_id)]
     elif not score and not cwe_id:
          df5 = df4[df4['Vulnerability Type(s)'].isin(vulne_type)]

     elif vulne_type and cwe_id:
          df5 = df4[df4['Vulnerability Type(s)'].isin(vulne_type) & df4['CWE ID'].isin(cwe_id)]
     elif vulne_type and score:
          df5 = df4[df4['Vulnerability Type(s)'].isin(vulne_type) & df4['Score'].isin(score)]
     elif score and cwe_id:
          df5 = df4[df4['Score'].isin(score) & df4['CWE ID'].isin(cwe_id)]

     else:
          df5 = df4[df4['CWE ID'].isin(cwe_id) & df4['Vulnerability Type(s)'].isin(vulne_type) & df4['Score'].isin(score)]


     st.write(df5)


     # PLOTS
     col1 , col2 = st.columns((2))
     with col1:
          # st.subheader("Distribution of CI SCORE")
          fig_col1 = px.histogram(df5['CI SCORE'],title='Distribution of CI SCORE')
          st.plotly_chart(fig_col1, use_container_width=True)

     with col2:
          group_by_year = df5.groupby('Year').count()['Score']
          fig_col2 = px.bar(group_by_year,x=group_by_year.index,y=group_by_year.values,color=group_by_year.index,title='Number of vulnerabilities by year')
          st.plotly_chart(fig_col2, use_container_width=True)


     col6 , col7 = st.columns((2))
     with col6:
          dictt = {
               'Score': [(i, i+1) for i in range(11)],
               'Number': [len(df[(df['Score'] >= i) & (df['Score'] < i+1)]) for i in range(11)]
          }
          df_dictt = pd.DataFrame(dictt)
          df_dictt['Score'] = df_dictt['Score'].apply(lambda x: x[0]) 
          fig_col6 = px.bar(df_dictt, x='Number', y='Score', text='Number',orientation='h',title='Score Range	by Vulnerabilities')
          st.plotly_chart(fig_col6, use_container_width=True)

     with col7:
          group_by_year = df5.groupby('Year').count()['Score']
          fig_col7 = px.line(group_by_year,x=group_by_year.index,y=group_by_year.values,markers='o',title='Number of vulnerabilities by year')
          st.plotly_chart(fig_col7, use_container_width=True)


     col3 , col4 , col5 = st.columns((3))
     with col3:
          fig_col3 = px.scatter(df5,x='Score',y='CI SCORE',color='Score',hover_data=['CI SCORE'],title='Scatter of CI SCORE by Score')
          st.plotly_chart(fig_col3, use_container_width=True)

     with col4:
          group_by_year = df5.groupby('Year')[['Score','Number Of Related Vulnerabilities']].mean()
          fig_col4 = px.line(group_by_year,x=group_by_year.index,y=['Score'],title='Score development')
          st.plotly_chart(fig_col4, use_container_width=True)

     with col5:
          group_by_label = df5.groupby('Label').count()[['Year','Score']]
          fig_col5 = px.pie(group_by_label,names=group_by_label.index,values='Year',title='Number of samples for each label')
          st.plotly_chart(fig_col5, use_container_width=True)





     #    PREDICTION PAGE     #

if selected=='Predict':
     st.title('Prediction page')


     df_predictions = pd.read_csv('sample_data_labeled_for_predictions.csv').replace(np.nan,'None')
     cols = ['Access', 'Complexity', 'Authentication', 'Conf.', 'Integ.', 'Avail','Score', 'Number Of Related Vulnerabilities']
     # 3 	 ['Remote' 'Local' 'Local Network'] 	 Access
     # 3 	 ['Medium' 'Low' 'High'] 	 Complexity
     # 2 	 ['Not required' 'Unknown'] 	 Authentication
     # 3 	 ['None' 'Partial' 'Complete'] 	 Conf.
     # 3 	 ['Partial' 'None' 'Complete'] 	 Integ.
     # 3 	 ['None' 'Partial' 'Complete'] 	 Avail

     st.sidebar.header(' Predict Vulnerability:')

     # Inputs
     access = st.selectbox('Access :', df_predictions['Access'].unique())
     complexity = st.selectbox('Complexity :', df_predictions['Complexity'].unique())
     authentication = st.selectbox('Authentication :', df_predictions['Authentication'].unique())
     conf = st.selectbox('Conf. :', df_predictions['Conf.'].unique())
     Integ = st.selectbox('Integ. :', df_predictions['Integ.'].unique())
     avail = st.selectbox('Avail :', df_predictions['Avail'].unique())
     score = st.selectbox('Score', df_predictions['Score'].unique())
     nb_related_vuln = st.number_input('Number Of Related Vulnerabilities :')
     input_data = {
          'Access': [access],
          'Complexity': [complexity],
          'Authentication': [authentication],
          'Conf.': [conf],
          'Integ.': [Integ],
          'Avail': [avail],
          'Score': [score],
          'Number Of Related Vulnerabilities': [nb_related_vuln]
     }
     df_input_data = pd.DataFrame(input_data,columns=cols)
     st.write(df_input_data)

     # Add the new record to our data sample for OHE and Scaling
     df_pred_input = pd.concat([df_predictions,df_input_data],axis=0).reset_index().drop(columns=['index'])
     numerical_columns = df_pred_input.select_dtypes(include=['int', 'float']).columns
     categorical_columns = df_pred_input.select_dtypes(exclude=['int', 'float']).columns

     # Process new input data for predict it
     mnScaler = MinMaxScaler()
     df_predictions_scaled = pd.concat([
          pd.get_dummies(df_pred_input[categorical_columns],dtype=float),
          pd.DataFrame(mnScaler.fit_transform(df_pred_input[numerical_columns]),columns=numerical_columns)
     ],axis=1)


     # Prediction
     filename = 'model.pkl'
     with open(filename, 'rb') as file:
          # model = pickle.load(file)
          model = joblib.load(file)
     pred = model.predict(df_predictions_scaled.tail(1))
     print('Prediction :',pred)
     # st.text(pred)
     if pred == 1:
          st.error('Yes, this vulnerability is targeted the critical infrastructure.')
     if pred == 0:
          st.success('No, this vulnerability is not targeted the critical infrastructure.')

     # # Prediction
     # def predict():
     #      filename = 'model.pkl'
     #      with open(filename, 'rb') as file:
     #           model = pickle.load(file)
     #      pred = model.predict(df_predictions_scaled.tail(1))
     #      print('Prediction :',pred)
     #      print('the function has applied')
     #      st.text(pred)
     #      if pred == 1:
     #           st.error('Yes, this vulnerability is targeted the critical infrastructure.')
     #      if pred == 0:
     #           st.success('No, this vulnerability is not targeted the critical infrastructure.')

     # st.button('Predict', on_click=predict)


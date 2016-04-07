from multiprocessing.pool import Pool

__author__ = 'liebesu'
import MySQLdb
def class_name(sha256):
    sha256=str(sha256).replace("\n","").replace("('","").replace("',)","")
    print sha256
    try:
        db= MySQLdb.connect(db="malware_info", user="root", passwd="polydata", host="localhost", port=3306)
        cursor = db.cursor()
        select_sql='select Virus_name from win_virus where sha256= "%s" limit 0,1 '%(sha256)
        cursor.execute(select_sql)
        virus_name=str(cursor.fetchall()).replace("(('", "").replace("',),)", "")
        if ":" in virus_name:
            class_name="low"
        else:
            tmp_name=virus_name.split('.')
            class_name=tmp_name[0]
        update_sql='update VT_detail set Category="%s" where sha256="%s"'%(class_name,sha256)
        cursor.execute(update_sql)
        db.commit()
        cursor.close()
        db.close()
    except Exception as e:
        cursor.close()
        db.close()
        print e
        pass
def get_sha256():
    try:
        db= MySQLdb.connect(db="malware_info", user="root", passwd="polydata", host="localhost", port=3306)
        cursor = db.cursor()
        select_sql='select sha256 from VT_detail where Category is  null'
        cursor.execute(select_sql)
        sha256s=cursor.fetchall()
        db.commit()
        cursor.close()
        db.close()
    except Exception as e:
        cursor.close()
        db.close()
        print e
    return sha256s


if __name__=="__main__":
    sha256s=get_sha256()
    print len(sha256s)
    '''for sha256 in sha256s:
        print sha256
        class_name(sha256)'''
    pool=Pool(processes=50)
    pool.map(class_name,sha256s)
    pool.close()
    pool.join()
    print "finish"

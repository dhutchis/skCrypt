fortune > bigfile.txt
for i in {1..10}
do
    echo -e "---" >> bigfile.txt;
    fortune >> bigfile.txt;
done

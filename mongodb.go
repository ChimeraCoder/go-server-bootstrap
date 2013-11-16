package main

import (
	"labix.org/v2/mgo"
	"os"
)

var (
	mongodb_session *mgo.Session

	MONGODB_URL      = os.Getenv("MONGODB_URL")
	MONGODB_DATABASE = os.Getenv("MONGODB_DATABASE")
	//Required in conf.go
	//MONGODB_URL string
	//MONGODB_DATABASE string
)

//Obtain a clean session for running mgo queries
func mongodbSession() (*mgo.Session, error) {
	//Very helpful tutorial can be found at http://denis.papathanasiou.org/?p=1090
	if mongodb_session == nil {
		var err error
		mongodb_session, err = mgo.Dial(MONGODB_URL)
		if err != nil {
			return nil, err
		}
	}
	return mongodb_session.Clone(), nil
}

//Given a collection name and a query (function) that runs on a collection, run
//the specified query function on the collection with the given name
//(f is usually an anonymous function that closes around the relevant variables)
func withCollection(collection_name string, f func(*mgo.Collection) error) error {
	//Again, see  http://denis.papathanasiou.org/?p=1090
	mgo_session, err := mongodbSession()
	if err != nil {
		return err
	}
	defer mgo_session.Close()
	coll := mgo_session.DB(MONGODB_DATABASE).C(collection_name)
	return f(coll)
}

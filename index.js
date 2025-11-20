const express = require("express");
const app = express();
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const port = process.env.PORT || 3000;

//middleware
app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@mycluster.eyaxb6h.mongodb.net/?appName=myCluster`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();

    const myDB = client.db("zap_shift_db");
    const parcelCollections = myDB.collection("parcels");

    //parcel api
    //post
    app.post("/parcels", async (req, res) => {
      const parcel = req.body;
      //parcel created time
      parcel.createdAt = new Date();
      const result = await parcelCollections.insertOne(parcel);
      res.send(result);
    });
    //get
    app.get("/parcels", async (req, res) => {
      const email = req.query.email;
      const result = await parcelCollections
        .find({ senderEmail: email }).sort({ createdAt: -1 })
        .toArray();
      res.send(result);
    });
    //delete
    app.delete("/parcels/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await parcelCollections.deleteOne(query);
      res.send(result);
    })

    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("zap-shift server is running!");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

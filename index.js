const express = require("express");
const app = express();
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET);
const port = process.env.PORT || 3000;
const crypto = require("crypto");

const generateRandomTrackingId = () => {
  const prefix = "PRCL";
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const random = crypto.randomBytes(3).toString("hex").toUpperCase();
  return `${prefix}-${date}-${random}`;
}

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
    const paymentCollections = myDB.collection("payments");

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
        .find({ senderEmail: email })
        .sort({ createdAt: -1 })
        .toArray();
      res.send(result);
    });
    //delete
    app.delete("/parcels/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await parcelCollections.deleteOne(query);
      res.send(result);
    });
    //find one
    app.get("/parcels/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await parcelCollections.findOne(query);
      res.send(result);
    });

    //stripe related api's here
    app.post("/create-checkout-session", async (req, res) => {
      const paymentInfo = req.body;
      const amount = parseInt(paymentInfo.cost) * 100;
      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            // Provide the exact Price ID (for example, price_1234) of the product you want to sell
            price_data: {
              currency: 'USD',
              unit_amount: amount,
              product_data: {
                name: paymentInfo.parcelName
              }
            },
            quantity: 1,
          },
        ],
        customer_email: paymentInfo.senderEmail,
        mode: "payment",
        metadata: {
          id: paymentInfo.id,
          parcelName: paymentInfo.parcelName,
        },
        success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-cancelled`,
      });
      console.log(session);
      res.send({ url: session.url });
    });

    // 
   app.patch("/payment-success", async (req, res) => {
  const sessionId = req.query.session_id;
  const session = await stripe.checkout.sessions.retrieve(sessionId);
  const trackingId = generateRandomTrackingId();

  if (session.payment_status === "paid") {

    const id = session.metadata.id;
    const filter = { _id: new ObjectId(id) };

    const updateDoc = {
      $set: {
        paymentStatus: "Paid",
        trackingId: trackingId,
      },
    };

    const result = await parcelCollections.updateOne(filter, updateDoc);

    const paymentHistory = {
      amount: session.amount_total / 100,
      currency: session.currency,
      customerEmail: session.customer_email,
      id: session.metadata.id,
      parcelName: session.metadata.parcelName,
      transactionId: session.payment_intent,
      paymentStatus: session.payment_status,
      paidAt: new Date()
    };

    const resultPayment = await paymentCollections.insertOne(paymentHistory);

    return res.send({
      success: true,
      trackingId,
      transactionId: session.payment_intent,
      paymentInfo: paymentHistory
    });
  }

  return res.status(400).send({ message: "Payment not successful" });
});





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

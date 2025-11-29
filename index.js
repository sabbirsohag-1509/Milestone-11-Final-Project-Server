const express = require("express");
const app = express();
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET);
const port = process.env.PORT || 3000;
const crypto = require("crypto");
const admin = require("firebase-admin");

// const serviceAccount = require("./zap-shift-firebase-adminsdk.json");
const { log } = require("console");

// const serviceAccount = require("./firebase-admin-key.json");
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8')
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const generateRandomTrackingId = () => {
  const prefix = "PRCL";
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const random = crypto.randomBytes(3).toString("hex").toUpperCase();
  return `${prefix}-${date}-${random}`;
};

//middleware
app.use(cors());
app.use(express.json());
const verifyFireBaseToken = async (req, res, next) => {
  // console.log("headers in the middleware", req.headers.authorization);
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).send({ message: "Unauthorized Access" });
  }
  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    console.log("decoded in the token", decoded);
    req.decoded_email = decoded.email;

    next();
  } catch (err) {
    return res.status(401).send({ message: "Unauthorized Access" });
  }
};

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
    // await client.connect();

    const myDB = client.db("zap_shift_db");
    const parcelCollections = myDB.collection("parcels");
    const paymentCollections = myDB.collection("payments");
    const userCollections = myDB.collection("users");
    const riderCollections = myDB.collection("riders");
    const trackingsCollections = myDB.collection("trackings");

    //middle admin before allowing admin access
    //added after verifyFireBaseToken middleware
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await userCollections.findOne(query);
      if (user?.role !== "Admin") {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    const logTrackingInfo = async (trackingId, status) => {
      const log = {
        trackingId,
        status,
        createdAt: new Date(),
        details: status.split("-").join(" "),
      };
      const result = await trackingsCollections.insertOne(log);
      return result;
    };

    //users related api
    //post
    app.post("/users", async (req, res) => {
      const user = req.body;
      user.role = "user";
      user.createdAt = new Date();
      const userExists = await userCollections.findOne({ email: user.email });
      if (userExists) {
        return res.send({ message: "User already exists" });
      }
      const result = await userCollections.insertOne(user);
      res.send(result);
    });
    //get
    app.get("/users", verifyFireBaseToken, async (req, res) => {
      const searchText = req.query.searchText || "";

      let query = {};

      if (searchText) {
        // $regex: searchText, $options: "i"
        query = {
          $or: [
            { displayName: { $regex: searchText, $options: "i" } },
            { email: { $regex: searchText, $options: "i" } },
          ],
        };
      }

      const result = await userCollections
        .find(query)
        .sort({ createdAt: 1 })
        .limit(3)
        .toArray();

      res.send(result);
    });

    //patch
    app.patch(
      "/users/:id/role",
      verifyFireBaseToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const roleInfo = req.body;
        const query = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            role: roleInfo.role,
          },
        };
        const result = await userCollections.updateOne(query, updateDoc);
        res.send(result);
      }
    );
    //get id
    app.get("/users/:id", async (req, res) => {});
    //get email/role
    app.get("/users/:email/role", async (req, res) => {
      const email = req.params.email;
      const query = { email };
      const user = await userCollections.findOne(query);
      res.send({ role: user?.role || "User" });
    });

    //parcel related api
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
      const deliveryStatus = req.query.deliveryStatus;

      let query = {};

      if (email) {
        query.senderEmail = email;
      }

      if (deliveryStatus) {
        query.deliveryStatus = deliveryStatus;
      }

      const result = await parcelCollections
        .find(query)
        .sort({ createdAt: -1 })
        .toArray();

      res.send(result);
    });
    //patch
    app.patch("/parcels/:id", async (req, res) => {
      const { riderId, riderName, riderEmail, parcelName, trackingId } =
        req.body;
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          deliveryStatus: "Rider Out for Delivery",
          riderId,
          riderName,
          riderEmail,
          parcelName,
          trackingId,
        },
      };
      const result = await parcelCollections.updateOne(query, updatedDoc);
      // updated rider information
      const riderQuery = { _id: new ObjectId(riderId) };
      const riderUpdateDoc = {
        $set: {
          workStatus: "On Delivery",
        },
      };
      const riderResult = await riderCollections.updateOne(
        riderQuery,
        riderUpdateDoc
      );
      //log tracking info
      await logTrackingInfo(trackingId, "Rider-Out-for-Delivery");
      res.send({ result, riderResult });
    });

    //delete
    app.delete("/parcels/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await parcelCollections.deleteOne(query);
      res.send(result);
    });
    //rider parcel delivery list api
    app.get("/parcels/rider", async (req, res) => {
      const { riderEmail, deliveryStatus } = req.query;
      const query = {};
      if (riderEmail) {
        query.riderEmail = riderEmail;
      }
      if (deliveryStatus) {
        query.deliveryStatus = deliveryStatus;
      }
      const result = await parcelCollections.find(query).toArray();
      res.send(result);
    });
    // update delivery status by rider
    app.patch("/parcels/:id/status", async (req, res) => {
      const { deliveryStatus, trackingId } = req.body;
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          deliveryStatus: deliveryStatus,
        },
      };
      const result = await parcelCollections.updateOne(query, updatedDoc);
      //log tracking info
      await logTrackingInfo(trackingId, deliveryStatus);
      res.send(result);
    });
    //find one
    app.get("/parcels/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await parcelCollections.findOne(query);
      res.send(result);
    });

    //pipeline..........Admin Dashboard Stats
    app.get("/parcels/delivery-status/stats", async (req, res) => {
      const pipeline = [
        {
          $group: {
            _id: "$deliveryStatus",
            count: { $sum: 1 },
          },
        },
        {
          $project: {
            // _id: 0,
            status: "$_id",
            count: 1,
          },
        },
      ];
      const result = await parcelCollections.aggregate(pipeline).toArray();
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
              currency: "USD",
              unit_amount: amount,
              product_data: {
                name: paymentInfo.parcelName,
              },
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

    // payment-success api
    app.patch("/payment-success", async (req, res) => {
      const sessionId = req.query.session_id;
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      //
      transactionId = session.payment_intent;
      const query = { transactionId: transactionId };
      const paymentExists = await paymentCollections.findOne(query);
      if (paymentExists) {
        return res.send({
          message: "Payment already Exists",
          transactionId: transactionId,
          trackingId: paymentExists.trackingId,
        });
      }
      //
      const trackingId = generateRandomTrackingId();
      if (session.payment_status === "paid") {
        const id = session.metadata.id;
        const filter = { _id: new ObjectId(id) };

        logTrackingInfo(trackingId, "Pending-Pickup");

        const updateDoc = {
          $set: {
            paymentStatus: "Paid",
            deliveryStatus: "Pending-Pickup",
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
          paidAt: new Date(),
          trackingId: trackingId,
        };

        const resultPayment = await paymentCollections.insertOne(
          paymentHistory
        );

        return res.send({
          success: true,
          trackingId,
          transactionId: session.payment_intent,
          paymentInfo: paymentHistory,
        });
      }

      return res.status(400).send({ message: "Payment not successful" });
    });
    //payment history
    app.get("/payment-history", verifyFireBaseToken, async (req, res) => {
      const email = req.query.email;
      //  console.log('headers:', req.headers);
      const result = await paymentCollections
        .find({ customerEmail: email })
        .sort({ paidAt: -1 })
        .toArray();
      //check email from token and query
      if (email !== req.decoded_email) {
        return res.status(403).send({ message: "forbidden access" });
      }
      res.send(result);
    });

    //riders related api
    //post
    app.post("/riders", async (req, res) => {
      const rider = req.body;
      rider.createdAt = new Date();
      rider.status = "Pending";
      const result = await riderCollections.insertOne(rider);
      res.send(result);
    });
    //get per day in rider dashboard
    app.get("/riders/delivery/per-day", async (req, res) => {
      const email = req.query.email;
      const date = req.query.date; // expected format: 'YYYY-MM-DD'
      const pipeline = [
        {
          $match: {
            riderEmail: email,
            deliveryStatus: "Rider Arriving",
          },
        },
        {
          $lookup: {
            from: "trackings",
            localField: "trackingId",
            foreignField: "trackingId",
            as: "parcel_trackings",
          },
        },
        {
          $unwind: "$parcel_trackings",
        },
        {
          $match: {
            "parcel_trackings.status": "Rider Arriving",
          },
        },
        {
          $addFields: {
            deliveryDay: {
              $dateToString: {
                format: "%Y-%m-%d",
                date: "$parcel_trackings.createdAt",
              },
            },
          }
        },
        {
          $group: {
            _id: "$deliveryDay",
            count: { $sum: 1 }, 
          },  
        }

      ];
      const result = await parcelCollections.aggregate(pipeline).toArray();
      res.send(result);
    });
    //get
    app.get("/riders", async (req, res) => {
      const { status, district, workStatus } = req.query;
      const query = {};
      if (status) {
        query.status = status;
      }
      if (district) {
        query.district = new RegExp(`^${district}$`, "i");
      }
      if (workStatus) {
        query.workStatus = workStatus;
      }
      const result = await riderCollections.find(query).toArray();
      res.send(result);
    });
    //patch
    app.patch(
      "/riders/:id",
      verifyFireBaseToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const status = req.body.status;
        const query = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            status: status,
            workStatus: status === "Approved" ? "Available" : "Not Available",
          },
        };
        const result = await riderCollections.updateOne(query, updateDoc);
        if (status === "Approved") {
          const email = req.body.email;
          const userQuery = { email };
          const updateUserDoc = {
            $set: {
              role: "Rider",
            },
          };
          const userResult = await userCollections.updateOne(
            userQuery,
            updateUserDoc
          );
          res.send({ result, userResult });
          return;
        }
        res.send(result);
      }
    );
    //delete
    app.delete("/riders/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await riderCollections.deleteOne(query);
      res.send(result);
    });

    //tracking related api
    app.get("/trackings/:trackingId/logs", async (req, res) => {
      const trackingId = req.params.trackingId;
      const query = { trackingId };
      const result = await trackingsCollections.find(query).toArray();
      res.send(result);
    });

    // Send a ping to confirm a successful connection

    // await client.db("admin").command({ ping: 1 });
    // console.log(
    //   "Pinged your deployment. You successfully connected to MongoDB!"
    // );
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("zap-shift server is running!");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

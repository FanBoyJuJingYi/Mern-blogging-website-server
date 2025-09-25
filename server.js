import 'dotenv/config';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import admin from 'firebase-admin';

import { getAuth } from 'firebase-admin/auth';
import { nanoid } from 'nanoid';
import aws from 'aws-sdk';
import fileUpload from 'express-fileupload';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import express from 'express';
import mongoose from 'mongoose';

//schema
import User from './Schema/User.js';
import Blog from './Schema/Blog.js';
import Notification from "./Schema/Notification.js";
import Comment from "./Schema/Comment.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const serviceAccountKey = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'reat-js-blog-website-firebase-adminsdk-pxagl-de1b80e4f8.json'), 'utf-8')
);



const server = express();
let PORT = 3000;

admin.initializeApp({
    credential: admin.credential.cert(serviceAccountKey),
});

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(express.json());
server.use(cors());

mongoose.connect(process.env.DB_LOCATION, {
    autoIndex: true,
});

const s3 = new aws.S3({
    region: 'ap-southeast-2',
    accessKeyId: process.env.KEY_2,
    secretAccessKey: process.env.KEY_1,
});

const generateUploadURL = async () => {
    const date = new Date();
    const imageName = `${nanoid()}-${date.getTime()}.jpeg`;

    return await s3.getSignedUrlPromise('putObject', {
        Bucket: 'blogging-website-1',
        Key: imageName,
        Expires: 1000,
        ContentType: 'image/jpeg',
    });
};

const formatDatatoSend = (user) => {
    const access_token = jwt.sign(
        { id: user._id, admin: user.admin },
        process.env.KEY_3
    ); // SECRET ACCESS KEY là mã để đối chiếu có phải là người dùng không
    return {
        access_token,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname: user.personal_info.fullname,
        isAdmin: user.admin
    };
};

const generateUsername = async (email) => {
    let username = email.split('@')[0];
    let isUsernameNotUniqe = await User.exists({
        'personal_info.username': username,
    }).then((result) => result);
    isUsernameNotUniqe ? (username += nanoid().substring(0, 5)) : '';
    return username;
};

// upload blog post
const verifyJWT = (req, res, next) => {
    const autheHeader = req.headers.authorization; // lấy token từ header
    const token = autheHeader && autheHeader.split(' ')[1]; // tách token từ header

    if (token == null) {
        return res.status(401).json({ error: "No access token " });
    } // nếu không có token thì trả về lỗi
    jwt.verify(token, process.env.KEY_3, (err, user) => {
        if (err) {
            return res.status(403).json({ error: "Invalid token" });
        }
        req.user = user.id;
        req.admin = user.admin
        next();
    });
}
// upload image url route

server.get('/get-upload-url', async (req, res) => {
    try {
        const uploadURL = await generateUploadURL(); // Gọi hàm để tạo URL tải lên từ Amazon S3
        res.status(200).json({ uploadURL }); // Trả về URL được tạo ra cho client
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: err.message });
    }
});



server.post('/signup', (req, res) => {
    let { fullname, email, password } = req.body;


    if (fullname.length < 3) {
        return res.status(403).json({ "error": "Fullname must be at least 3 letters long" })
    }
    if (!email.length) {
        return res.status(403).json({ "error": "Enter email" })
    }
    if (!emailRegex.test(email)) {
        return res.status(403).json({ "error": "Email is invalid" })
    }
    if (!passwordRegex.test(password)) {
        return res.status(403).json({ "error": "Password should be 6 to 20 characters long with a numberic, 1 lowercase and 1 uppercase letters" })
    }

    bcrypt.hash(password, 10, async (err, hashed_password) => {
        let username = await generateUsername(email);

        let user = new User({
            personal_info: { fullname, email, username, password: hashed_password },
        });

        user
            .save()
            .then((u) => {
                return res.status(200).json(formatDatatoSend(u));
            })
            .catch((err) => {
                if (err.code == 11000) {
                    return res.status(500).json({ error: 'Email already exists' });
                }
                return res.status(500).json({ error: err.message });
            });
    });
});

server.post('/signin', (req, res) => {
    let { email, password } = req.body;
    User.findOne({ 'personal_info.email': email })
        .then((user) => {
            if (!user) {
                return res.status(403).json({ error: 'Email not found' });
            }
            if (!user.google_auth) {
                bcrypt.compare(password, user.personal_info.password, (err, result) => {

                    if (err) {
                        return res
                            .status(403)
                            .json({ err: 'Error occured while login please try agian' });
                    }
                    if (!result) {
                        return res.status(403).json({ error: 'Incorrect password' });
                    } else {
                        return res.status(200).json(formatDatatoSend(user));
                    }
                });
            } else {
                return res.status(403).json({
                    error: 'Account was created using google. Try logging in with google',
                });
            }
        })
        .catch((err) => {
            console.log(err.message);
            return res.status(500).json({ error: err.message });
        });
});

server.post("/change-password", verifyJWT, (req, res) => {
    let { currentPassword, newPassword } = req.body;

    if (!passwordRegex.test(currentPassword) || passwordRegex.test(newPassword)) {
        return res.status(403).json({ error: "Password should be 6 to 20 characters long with a numberic, 1 lowercase and 1 uppercase letters" })
    }
    User.findOne({ _id: req.user })
        .then((user) => {
            if (user.google_auth) {
                return res.status(403).json({ error: "You cant't change account's password beacause you logged in through google" })
            }
            bcrypt.compare(currentPassword, user.personal_info.password, (err, result) => {
                if (err) {
                    return res.status(500).json({ error: "Some error occred while changing the password, please try again later" })
                }
                if (!result) {
                    return res.status(403).json({ error: "Incorrect current password" })
                }
                bcrypt.hash(newPassword, 10, (err, hashed_password) => {
                    User.findOneAndUpdate({ _id: req.user }, { "personal_info.password": hashed_password })
                        .then((u) => {
                            return res.status(200).json({ status: 'password changed' })
                        })
                        .catch(err => {
                            return res.status(500).json({ error: "Some error occured while saving the password, please try again later" })
                        })
                })
            })
        })
        .catch(err => {
            console.log(err);
            return res.status(500).json({ error: "User not found" })
        })

})

server.post('/google-auth', async (req, res) => {
    let { access_token } = req.body;
    getAuth()
        .verifyIdToken(access_token)
        .then(async (decodedUser) => {
            let { email, name, picture } = decodedUser;

            picture = picture.replace('s96-c', 's384-c');

            let user = await User.findOne({ 'personal_info.email': email })
                .select(
                    'personal_info.fullname personal_info.username personal_info.profile_img google_auth'
                )
                .then((u) => {
                    return u || null;
                })
                .catch((err) => {
                    return res.status(500).json({ error: err.message });
                });
            if (user) {
                if (!user.google_auth) {
                    return res.status(403).json({
                        error:
                            'This email was signed up without google. Please log in with password to access the account',
                    });
                }
            } else {
                let username = await generateUsername(email);
                user = new User({
                    personal_info: {
                        fullname: name,
                        email,
                        profile_img: picture,
                        username,
                    },
                    google_auth: true,
                });

                await user
                    .save()
                    .then((u) => {
                        user = u;
                    })
                    .catch((err) => {
                        return res.status(403).json({ error: err.message });
                    });
            }
            return res.status(200).json(formatDatatoSend(user));
        })
        .catch((err) => {
            return res.status(500).json({
                error:
                    'Failed to authenticate you with goole. Try with some other google account',
            });
        });
});

// upload image to client and then to s3

server.use(
    fileUpload({
        useTempFiles: true,
        tempFileDir: path.join(__dirname, './tmp'),
    })
);

const KEY_2 = process.env.KEY_2;
const KEY_1 = process.env.KEY_1;
const S3_REGION = 'ap-southeast-2';
const S3_BUCKET_NAME = 'blogging-website-1';

const client = new S3Client({
    region: S3_REGION,
    credentials: {
        accessKeyId: KEY_2,
        secretAccessKey: KEY_1,
    },
});

// upload img to imageKey
server.post('/upload', async (req, res) => {
    try {
        if (!req.files || Object.keys(req.files).length === 0) {
            return res.status(400).send('No files were uploaded.');
        }

        const { mimetype, tempFilePath } = req.files.img;

        const date = new Date();
        const fileKey = `${nanoid()}-${date.getTime()}`;
        const fileStream = fs.createReadStream(tempFilePath);

        const uploadClient = new Upload({
            client: client,
            params: {
                Bucket: S3_BUCKET_NAME,
                Key: fileKey,
                ContentType: mimetype,
                Body: fileStream,
            },
        });

        await uploadClient.done();
        res.send(fileKey);
        // client lay fileKey tu response de request len /upload/<fileKey> de xem hinh
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: err.message });
    }
});

server.get('/upload/:imageKey', async (req, res) => {
    try {
        const { imageKey } = req.params;

        const command = new GetObjectCommand({
            Bucket: S3_BUCKET_NAME,
            Key: imageKey,
        });

        const response = await client.send(command);
        const data = await response.Body.transformToByteArray();
        const buffer = Buffer.from(data);

        res.writeHead(200, { 'Content-Type': 'image/jpeg' });
        res.write(buffer, 'binary');
        res.end(null, 'binary');
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: err.message });
    }
});

// get blog
server.post('/latest-blogs', (req, res) => {

    let { page } = req.body;

    let maxLimit = 5;

    Blog.find({ draft: false })
        .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title des banner activity tags publishedAt -_id")
        .skip((page - 1) * maxLimit)
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/all-latest-blogs-count", (req, res) => {
    Blog.countDocuments({ draft: false })
        .then(count => {
            return res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message });
        })
})

server.post("/search-blogs", (req, res) => {
    let { tag, page, author, query, limit, eliminate_blog } = req.body;
    let findQuery;
    if (tag) {
        findQuery = { tags: tag, draft: false, blog_id: { $ne: eliminate_blog } };
    } else if (query) {
        findQuery = { title: new RegExp(query, 'i'), draft: false };
    } else if (author) {
        findQuery = { author, draft: false }
    }
    let maxLimit = limit ? limit : 5;
    Blog.find(findQuery)
        .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title des banner activity tags publishedAt -_id")
        .skip((page - 1) * maxLimit)
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/search-blogs-count", (req, res) => {

    let { tag, author, query } = req.body;
    let findQuery;
    if (tag) {
        findQuery = { tags: tag, draft: false };
    } else if (query) {
        findQuery = { title: new RegExp(query, 'i'), draft: false };
    } else if (author) {
        findQuery = { author, draft: false }
    }

    Blog.countDocuments(findQuery)
        .then(count => {
            return res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message })
        })
})
server.post("/search-users", async (req, res) => {
    try {
        const query = req.body.query;
        if (!query || typeof query !== 'string') {
            return res.status(400).json({ error: "Invalid query parameter" });
        }

        const users = await User.find({
            "personal_info.fullname": { $regex: query, $options: 'i' }
        })
            .limit(2)
            .select("personal_info.fullname personal_info.username personal_info.profile_img -_id")
            .exec();

        return res.status(200).json({ users });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

//trending blogs

server.get("/trending-blogs", (req, res) => {
    Blog.find({ draft: false })
        .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img -_id")
        .sort({ "activity.total_read": -1, "activity.total_likes": -1, "publishedAt": -1 })
        .select("blog_id title publishedAt -_id")
        .limit(5)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        })

})

server.post("/get-profile", (req, res) => {
    let { username } = req.body;
    User.findOne({ "personal_info.username": username })
        .select("-personal_info.password -google_auth --updateAt -blogs")
        .then(user => {
            res.status(200).json(user)
        })
        .catch(err => {
            console.log(err)
            return res.status(500).json({ error: err.message })
        })
})

server.post("/update-profile-img", verifyJWT, (req, res) => {
    let { url } = req.body;
    User.findOneAndUpdate({ _id: req.user }, { "personal_info.profile_img": url })
        .then(() => {
            return res.status(200).json({ profile_img: url })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/update-profile", verifyJWT, (req, res) => {
    let { username, bio, social_links } = req.body;
    let bioLimit = 150
    if (username.length < 3) {
        return res.status(403).json({ error: "Username should be at least 3  letters long" })
    }
    if (bio.length > bioLimit) {
        return res.status(403).json({ error: `Bio should not be more than ${bioLimit} characters` })
    }
    let socialLinksArr = Object.keys(social_links);

    try {
        for (let i = 0; i < socialLinksArr.length; i++) {
            if (social_links[socialLinksArr[i]].length) {
                let hostname = new URL(social_links[socialLinksArr[i]]).hostname;

                if (!hostname.includes(`${socialLinksArr[i]}.com}`) && socialLinksArr[i] != 'website') {
                    return res.status(403).json({ error: `${socialLinksArr[i]} link is invalid. You must enter a full link` })
                }
            }
        }
    } catch (err) {
        return res.status(500).json({ error: "You must provide full socail links with http(s) included" })
    }
    let UpdateObj = {
        "personal_info.username": username,
        "personal_info.bio": bio,
        social_links
    }
    User.findOneAndUpdate({ _id: req.user }, UpdateObj, {
        runValidators: true
    })
        .then(() => {
            return res.status(200).json({ username })
        })
        .catch(err => {
            if (err.code == 11000) {
                return res.status(409).json({ error: "username is already taken" })
            }
            return res.status(500).json({ error: err.message })
        })
})

// upload blog
server.post('/create-blog', verifyJWT, (req, res) => {
    let authorID = req.user; // lấy id của người dùng từ token
    let isAdmin = req.admin
    if (isAdmin) {
        let { title, content, des, banner, tags, draft, id } = req.body;

        if (!title.length) {
            return res.status(403).json({ error: "You must provide a title" });
        }

        if (!draft) {
            if (!des.length || des.length > 200) {
                return res.status(403).json({ error: "You must provide blog description under 200 charaters" });
            }
            if (!banner.length) {
                return res.status(403).json({ error: "You must provide blog banner to publish it" });
            }
            if (!content.blocks.length) {
                return res.status(403).json({ error: "There must be some blog content to publish it" });
            }
            if (!tags.length || tags.length > 10) {
                return res.status(403).json({ error: "Provide tags in order to publish the blog, Maximum 10" });
            }
        }

        tags = tags.map((tag) => tag.toLowerCase()); // để cho khỏi đầy bộ nhớ ví dụ như "React" và "react" là 2 thằng khác nhau

        let blog_id = id || title.replace(/[^a-zA-Z0-9]/g, '-').replace(/\s+/g, '-').trim() + nanoid(); // tạo id cho blog 

        if (id) {
            Blog.findOneAndUpdate({ blog_id }, { title, des, banner, content, tags, draft: draft ? draft : false })
                .then(() => {
                    return res.status(200).json({ id: blog_id })
                })
                .catch(err => {
                    return res.status(500).json({ error: err.message })
                })
        }
        else {
            let blog = new Blog({
                title, banner, des, content, tags, author: authorID, blog_id, draft: Boolean(draft)
            })
            blog.save().then(blog => {
                let incrementVal = draft ? 0 : 1;
                User.findOneAndUpdate({ _id: authorID }, { $inc: { "account_info.total_posts": incrementVal }, $push: { "blogs": blog._id } }) // tăng số lượng bài viết của người dùng
                    .then(user => {
                        return res.status(200).json({ id: blog.blog_id });
                    })
                    .catch(err => {
                        return res.status(500).json({ error: "Failed to update total posts number" });
                    })
            })
                .catch(err => {
                    return res.status(500).json({ error: err.message });
                })
        }

    } else {
        return res.status(500).json({ error: "you don't have permissions to create any blogs" })
    }



})

server.post("/get-blog", (req, res) => {
    let { blog_id, draft, mode } = req.body;
    let incrementVal = mode != 'edit' ? 1 : 0;

    Blog.findOneAndUpdate({ blog_id }, { $inc: { "activity.total_reads": incrementVal } })
        .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img")
        .select("title des content tags banner activity publishedAt blog_id")
        .then(blog => {
            User.findOneAndUpdate({ "personal_info.username": blog.author.personal_info.username },
                {
                    $inc: { "account_info.total_reads": incrementVal }
                })
                .catch(err => {
                    return res.status(500).json({ error: err.message })
                })
            if (blog.draft && !draft) {
                return res.status(500).json({ error: "You can not access draft blogs" })
            }
            return res.status(200).json({ blog })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})


server.post("/like-blog", verifyJWT, (req, res) => {
    let user_id = req.user

    let { _id, islikedByUser } = req.body

    let incrementVal = !islikedByUser ? 1 : -1;

    Blog.findOneAndUpdate({ _id }, { $inc: { "activity.total_likes": incrementVal } })
        .then(blog => {
            if (!islikedByUser) {
                let like = new Notification({
                    type: "like",
                    blog: _id,
                    notification_for: blog.author,
                    user: user_id
                })
                like.save().then(notification => {
                    return res.status(200).json({ liked_by_user: true })
                })
            }
            else {
                Notification.findOneAndDelete({ user: user_id, blog: _id, type: "like" })
                    .then(data => {
                        return res.status(200).json({ like_by_user: false })
                    })
                    .catch(err => {
                        return res.status(500).json({ error: err.message })
                    })
            }
        })


})

server.post("/isliked-by-user", verifyJWT, (req, res) => {
    let user_id = req.user
    let { _id } = req.body

    Notification.exists({ user: user_id, type: "like", blog: _id })
        .then(result => {
            return res.status(200).json({ result })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/add-comment", verifyJWT, (req, res) => {
    let user_id = req.user
    let { _id, comment, blog_author, replying_to, notification_id } = req.body

    if (!comment.length) {
        return res.status(403).json({ error: 'Write something to leave a comment ...' })
    }

    let commentObj = {
        blog_id: _id, blog_author, comment, commented_by: user_id
    }

    if (replying_to) {
        commentObj.parent = replying_to;
        commentObj.isReply = true;
    }

    new Comment(commentObj).save().then(async commentFile => {
        let { comment, commentedAt, children } = commentFile;

        Blog.findOneAndUpdate({ _id }, { $push: { "comments": commentFile._id }, $inc: { "activity.total_comments": 1, "activity.total_parent_comments": replying_to ? 0 : 1 } })
            .then(blog => {
                console.log("New comment created")
            })
        let notificationObj = {
            type: replying_to ? "reply" : "comment",
            blog: _id,
            notification_for: blog_author,
            user: user_id,
            comment: commentFile.id
        }

        if (replying_to) {
            notificationObj.replied_on_comment = replying_to;
            await Comment.findOneAndUpdate({ _id: replying_to }, { $push: { children: commentFile._id } })
                .then(replyingToCommentDoc => {
                    notificationObj.notification_for = replyingToCommentDoc.commented_by
                })
            if (notification_id) {
                Notification.findOneAndUpdate({ _id: notification_id }, { reply: commentFile._id })
                    .then(notification => {
                        console.log("Notification Updated")
                    })
            }
        }

        new Notification(notificationObj).save().then(notification => console.log('New notification created'))

        return res.status(200).json({ comment, commentedAt, _id: commentFile._id, user_id, children })

    })

})


server.post("/get-blog-comments", (req, res) => {
    let { blog_id, skip } = req.body;

    let maxLimit = 5;
    Comment.find({ blog_id, isReply: false })
        .populate("commented_by", "personal_info.fullname personal_info.username personal_info.profile_img")
        .skip(skip)
        .limit(maxLimit)
        .sort({
            'commentedAt': -1
        })
        .then(comment => {
            return res.status(200).json(comment);
        })
        .catch(err => {
            console.log(err);
            return res.status(500).json({ error: err.message })
        })
})

server.post("/get-replies", (req, res) => {
    let { _id, skip } = req.body;
    let maxLimit = 5;
    Comment.findOne({ _id })
        .populate({
            path: "children",
            options: {
                limit: maxLimit,
                skip: skip,
                sort: { "commentedAt": -1 }
            },
            populate: {
                path: 'commented_by',
                select: "personal_info.profile_img personal_info.fullname personal_info.username"
            },
            select: "-blog_id -updateAt"
        })
        .select("children")
        .then(doc => {
            return res.status(200).json({ replies: doc.children })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })

})

const deleteComments = (_id) => {
    Comment.findOneAndDelete({ _id })
        .then(comment => {
            if (comment.parent) {
                Comment.findOneAndUpdate({ _id: comment.parent }, { $pull: { children: _id } })
                    .then(data => console.log('comment delete from parent'))
                    .catch(err => console.log(err.message))
            }

            Notification.findOneAndDelete({ comment: _id }).then(notification => console.log('comment notification deleted'))

            Notification.findOneAndUpdate({ reply: _id }, { $unset: { reply: 1 } }).then(notification => console.log('reply notification deleted'))

            Blog.findOneAndUpdate({ _id: comment.blog_id }, { $pull: { comments: _id }, $inc: { "activity.total_comments": -1 }, "activity.total_parent_comments": comment.parent ? 0 : -1 })
                .then(blog => {
                    if (comment.children.length) {
                        comment.children.map(replies => {
                            deleteComments(replies)
                        })
                    }
                })
                .catch(err => {
                    console.log(err.message)
                })
        })
}


server.post("/delete-comment", verifyJWT, (req, res) => {
    let user_id = req.user
    let isAdmin = req.admin
    let { _id } = req.body

    if (isAdmin) {
        Comment.findOne({ _id })
            .then(comment => {
                if (user_id == comment.commented_by || user_id == comment.blog_author) {
                    deleteComments(_id);
                    return res.status(200).json({ status: 'done' })
                } else {
                    return res.status(403).json({ error: "You can not delete this comment" })
                }
            })

    } else {
        return res.status(500).json({ error: "you don't have permissions to delete the blog" })
    }



})

server.get("/new-notification", verifyJWT, (req, res) => {
    let user_id = req.user
    Notification.exists({ notification_for: user_id, seen: false, user: { $ne: user_id } })
        .then(result => {
            if (result) {
                return res.status(200).json({ "new_notification_available": true })
            } else {
                return res.status(200).json({ "new_notification_available": false })
            }
        })
        .catch(err => {
            console.log(err.message)
            return res.status(500).json({ error: err.message })
        })

})

server.post("/notifications", verifyJWT, (req, res) => {
    let user_id = req.user;
    let { page, filter, deletedDocCount } = req.body
    let maxLimit = 10;
    let findQuery = { notification_for: user_id, user: { $ne: user_id } }
    let skipDocs = (page - 1) * maxLimit;
    if (filter != 'all') {
        findQuery.type = filter;
    }
    if (deletedDocCount) {
        skipDocs -= deletedDocCount;
    }

    Notification.find(findQuery)
        .skip(skipDocs)
        .limit(maxLimit)
        .populate("blog", "title blog_id")
        .populate("user", "personal_info.fullname personal_info.username personal_info.profile_img")
        .populate("comment", "comment")
        .populate("replied_on_comment", "comment")
        .populate("reply", "comment")
        .sort({ createdAt: -1 })
        .select("createdAt type seen reply")
        .then(notifications => {
            Notification.updateMany(findQuery, { seen: true })
                .skip(skipDocs)
                .limit(maxLimit)
                .then(() => console.log('notification seen'))
            return res.status(200).json({ notifications })

        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })

})

server.post("/all-notifications-count", verifyJWT, (req, res) => {
    let user_id = req.user;

    let { filter } = req.body;
    let findQuery = { notification_for: user_id, user: { $ne: user_id } }

    if (filter != 'all') {
        findQuery.type = filter;
    }
    Notification.countDocuments(findQuery)
        .then(count => {
            return res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/user-written-blogs", verifyJWT, (req, res) => {
    let user_id = req.user;

    let { page, draft, query, deletedDocCount } = req.body;

    let maxLimit = 5;
    let skipDocs = (page - 1) * maxLimit;
    if (deletedDocCount) {
        skipDocs -= deletedDocCount
    }

    Blog.find({ author: user_id, draft, title: new RegExp(query, 'i') })
        .skip(skipDocs)
        .limit(maxLimit)
        .sort({ publishedAt: -1 })
        .select("title banner publishedAt blog_id activity des draft -_id")
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/user-written-blogs-count", verifyJWT, (req, res) => {
    let user_id = req.user

    let { draft, query } = req.body

    Blog.countDocuments({ author: user_id, draft, title: new RegExp(query, 'i') })
        .then(count => {
            return res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/delete-blog", verifyJWT, (req, res) => {
    let user_id = req.user
    let { blog_id } = req.body
    Blog.findOneAndDelete({ blog_id })
        .then(blog => {
            Notification.deleteMany({ blog: blog._id }).then(data => console.log('notification deleted'))
            Comment.deleteMany({ blog: blog._id }).then(data => console.log("comment deleted"));
            User.findOneAndUpdate({ _id: user_id }, { $pull: { blog: blog._id }, $inc: { "account_info.total_posts": -1 } })
                .then(user => console.log('Blog deleted'))

            return res.status(200).json({ status: 'done' })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

// ======== server start done===============
server.listen(PORT, () => {
    console.log('listening on port ->' + PORT);
});

export default server;

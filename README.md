# Create your Final MERN Showcase App

This is the last exercise of the entire **MERN** course which will take multiple days to complete and should encompass every skill you have learned in this course, particularly how to put all the parts together get a **M**ongoDB database connected to a **N**ode/**E**xpress backend serving a **R**eact frontend, all running in the cloud at Heroku and MongoDB Atlas.

## Instructions

- to begin, follow these instructions: [Create React app with user authentication and authorization](https://onespace.netlify.app/howtos?id=446)
- this will set up a frontend and backend site which allows users to log in on the React site
- the backend API has information on each user regarding what group they belong to
- depending on the group, each user can see different content and has different rights on the React site

## Build in all features from previous exercises

- front and backend at Heroku
    - e.g. `mernshowcase-et-frontend` (where `et` are your initials)
    - e.g. `mernshowcase-et-backend` (where `et` are your initials)

- required features 
    - **Node**/**Express** API backend with React Router - *see [ex416](https://onespace.netlify.app/howtos?id=416) and [ex506](https://github.com/FbW-D01/Exercise-506-BE-SER-createSupplierAPIAndWebsite)*
    - **React** frontend with **React Router** - *see [these instructions](https://reactrouter.com/docs/en/v6/getting-started/installation)*
    - **MVC with Mongoose** - *see [ex516](https://github.com/FbW-D01/Exercise-516-BE-ADV-createConferenceLandingPageSiteWithNodeExpressEJSMongooseMVC)*
    - **data validation/sanitation** - *see [ex519](https://github.com/FbW-D01/Exercise-519-BE-SEC-createAReactFormThatValidatesData)*
    - **authentication**:login/logout with **sessions/cookies** - *see [ex521](https://github.com/FbW-D01/Exercise-521-BE-SEC-createAnAPIThatEnablesAUserToLoginAndStayLoggedIn)*
    - **authorization**: use management with **access groups** - *see [this project](https://onespace.netlify.app/howtos?id=446)*
    - **bcrypt** password hashing - *see [ex520](https://github.com/FbW-D01/Exercise-520-BE-SEC-createUserSignUpAndLogin)*
    - **new user signup process** - *see [ex520](https://github.com/FbW-D01/Exercise-520-BE-SEC-createUserSignUpAndLogin) and [this project](https://onespace.netlify.app/howtos?id=446)*
    - **new user approval process** - *use [this project](https://onespace.netlify.app/howtos?id=446) as a basis, allow admin users to view list of new users and click a `[Approve]` or `[Decline]` button for each*
    - deploy backend/frontend/database to **Heroku and MongoDB Atlas** - *see [ex507](https://github.com/FbW-D01/Exercise-507-BE-SER-createAndPublishSitesAtHeroku) and [ex514](https://github.com/FbW-D01/Exercise-514-BE-ADV-publishUserAPIAndUserFrontendToHeroku)*
    
## 💪 CHALLENGES: Optional Features

- JWT - *see [this project](https://onespace.netlify.app/howtos?id=450)*
- user can change password - *as a basis, use [this project](https://onespace.netlify.app/howtos?id=446)*
- user can delete account - *as a basis, use [this project](https://onespace.netlify.app/howtos?id=446)*
- admin can create/edit/delete users - *as a basis, use [this project](https://onespace.netlify.app/howtos?id=446)*
- email notification for signups - *see [node-mailer](https://www.npmjs.com/package/nodemailer)*
   - 1. user signs up
   - 2. receives mail with link
   - 3. link goes to endpoint
   - 4. endpoint changes accessGroup from `notYetApprovedUsers` to `members`
- implement socket.io - *see [these instructions](https://socket.io/get-started/chat)*
   - users who are waiting to be approved are approved in real time without having to log out and log in again
   - members can see who else is online
   - members can chat with each other
- allow users to upload images - *see [this video](https://www.youtube.com/watch?v=srPXMt1Q0nY&list=PL55RiY5tL51q4D-B63KBnygU6opNPFk_q&index=10)*

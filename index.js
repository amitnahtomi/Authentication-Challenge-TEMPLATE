/* write the code to run app.js here */
const port = process.env.PORT || 8080;
const app = require('./app')

app.listen(port, () => {
    console.log(`app listening at http://localhost:${port}`)
  });
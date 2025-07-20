import { MailtrapClient } from "mailtrap";



export const mailtrapClient = new MailtrapClient({
  token: process.env.MAILTRAP_TOKEN
})

// custom domain involving name.com - this is to allow other emails
// apart from the one used to register with mailtrap
export const sender = {
    email: "hello@subdomain.advancedauth.live",
    name: "Mailtrap Test",
}



//demo domain - edet.aniebiet@lmu.edu.ng
// export const sender = {
//   email: "hello@demomailtrap.co",
//   name: "Mailtrap Test",
// };

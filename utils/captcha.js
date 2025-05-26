const config = require("../config/config");
const colors = require("colors");
const axios = require("axios");

const solve2Captcha = async (params) => {
  let retries = 5;
  try {
    // Step 1: Create a CAPTCHA task
    const taskResponse = await axios.post(
      "https://api.2captcha.com/createTask",
      {
        clientKey: config.API_KEY_2CAPTCHA,
        task: {
          type: "TurnstileTaskProxyless",
          websiteURL: params.websiteURL,
          websiteKey: params.websiteKey,
        },
      },
      {
        headers: { "Content-Type": "application/json" },
      }
    );

    const requestId = taskResponse.data.taskId;
    if (!requestId) throw new Error(`Task creation failed: ${JSON.stringify(taskResponse.data)}`);

    // Step 2: Poll for the result
    let result;
    do {
      await new Promise((resolve) => setTimeout(resolve, 10000));
      const resultResponse = await axios.post(
        "https://api.2captcha.com/getTaskResult",
        {
          clientKey: config.API_KEY_2CAPTCHA,
          taskId: requestId,
        },
        {
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      result = resultResponse.data;
      if (result.status === "processing") {
        console.log(colors.yellow("CAPTCHA still processing..."));
      }
      retries--;
    } while (result.status === "processing" && retries > 0);

    // Step 3: Use the CAPTCHA solution
    if (result.status === "ready") {
      console.log(colors.green("CAPTCHA success.."));
      return result.solution.token; // This is the CAPTCHA token
    } else {
      console.error("Error captcha:", result);
      return null;
    }
  } catch (error) {
    console.error("Error captcha:", error.message);
    return null;
  }
};

const solveAntiCaptcha = async (params) => {
  let retries = 5;
  try {
    // Step 1: Create a CAPTCHA task
    const taskResponse = await axios.post(
      "https://api.anti-captcha.com/createTask",
      {
        clientKey: config.API_KEY_ANTI_CAPTCHA,
        task: {
          type: "TurnstileTaskProxyless",
          websiteURL: params.websiteURL,
          websiteKey: params.websiteKey,
        },
      },
      {
        headers: { "Content-Type": "application/json" },
      }
    );

    const requestId = taskResponse.data.taskId;
    if (!requestId) {
      throw new Error("Failed to create CAPTCHA task. No task ID returned.");
    }

    // Step 2: Poll for the result
    let result;
    do {
      await new Promise((resolve) => setTimeout(resolve, 10000));
      const resultResponse = await axios.post(
        "https://api.anti-captcha.com/getTaskResult",
        {
          clientKey: config.API_KEY_ANTI_CAPTCHA,
          taskId: requestId,
        },
        {
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      result = resultResponse.data;
      if (result.status === "processing") {
        console.log(colors.yellow("CAPTCHA still processing..."));
      }
      retries--;
    } while (result.status === "processing" && retries > 0);

    // Step 3: Use the CAPTCHA solution
    if (result.status === "ready") {
      console.log(colors.green("CAPTCHA success.."));
      return result.solution.token; // This is the CAPTCHA token
    } else {
      console.error("Error captcha:", result);
      return null;
    }
  } catch (error) {
    console.error("Error captcha:", error.message);
    return null;
  }
};

const solveMonsterCaptcha = async (params) => {
  let retries = 5;
  try {
    // Step 1: Create a CAPTCHA task
    const taskResponse = await axios.post(
      "https://api.capmonster.cloud/createTask",
      {
        clientKey: config.API_KEY_CAPMONSTER,
        task: {
          type: "TurnstileTaskProxyless",
          websiteURL: params.websiteURL,
          websiteKey: params.websiteKey,
        },
      },
      {
        headers: { "Content-Type": "application/json" },
      }
    );

    const requestId = taskResponse.data.taskId;
    if (!requestId) {
      throw new Error("Failed to create CAPTCHA task. No task ID returned.");
    }

    // Step 2: Poll for the result
    let result;
    do {
      await new Promise((resolve) => setTimeout(resolve, 10000));
      const resultResponse = await axios.post(
        "https://api.capmonster.cloud/getTaskResult",
        {
          clientKey: config.API_KEY_CAPMONSTER,
          taskId: requestId,
        },
        {
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      result = resultResponse.data;
      if (result.status === "processing") {
        console.log(colors.yellow("CAPTCHA still processing..."));
      }
      retries--;
    } while (result.status === "processing" && retries > 0);

    // Step 3: Use the CAPTCHA solution
    if (result.status === "ready") {
      console.log(colors.green("CAPTCHA success.."));
      return result.solution.token; // This is the CAPTCHA token
    } else {
      console.error("Error captcha:", result);
      return null;
    }
  } catch (error) {
    console.error("Error captcha:", error.message);
    return null;
  }
};

async function solveCaptcha(
  params = {
    websiteURL: config.CAPTCHA_URL,
    websiteKey: config.WEBSITE_KEY,
  }
) {
  if (config.TYPE_CAPTCHA === "2captcha") {
    return await solve2Captcha(params);
  } else if (config.TYPE_CAPTCHA === "anticaptcha") {
    return await solveAntiCaptcha(params);
  } else if (config.TYPE_CAPTCHA === "monstercaptcha") {
    return await solveMonsterCaptcha(params);
  }
  console.log(colors.red("Invalid type captcha"));
  return null;
}

module.exports = { solveCaptcha };

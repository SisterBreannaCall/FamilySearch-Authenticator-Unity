using System;
using UnityEngine;
using System.Net;
using System.Text;
using Newtonsoft.Json;
using System.Collections;
using AccessTokenResource;
using FamilySearchMemories;
using UnityEngine.Networking;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

public class FamilySearchAuth : MonoBehaviour
{
    public static FamilySearchAuth Instance { get; set; }

#if UNITY_WEBGL
    [DllImport("__Internal")]
    private static extern void StartAuthentication(string authRequest);
#elif UNITY_EDITOR || UNITY_STANDALONE_WIN
    private HttpListener httpListener;
#endif

    private Uri baseUri;
    private UnityWebRequest webRequest;
    private string pidToLoad;
    private string code_verifier;
    private string code_challenge;
    private string authorizationCode;
    private AccessToken accessToken;
    private const string outState = "237589753";
    private UnityWebRequestAsyncOperation asyncOperation;
    private Environment devEnvironment = Environment.Production;
    private const string client_id = "";
    private string userID;
    private bool pedigreeFinished = true;
    private bool descendentFinished = true;
    private bool exchangeFinished = true;
    private bool isFirstLoad = true;

    private enum Environment
    {
        Production,
        Beta,
        Integration
    }

    private void Awake()
    {
        if (Instance != null)
        {
            Destroy(gameObject);
            return;
        }

        Instance = this;
        DontDestroyOnLoad(gameObject);
    }

    private void SetBaseURL(string setType)
    {
        if (setType == "Auth")
        {
            switch (devEnvironment)
            {
                case Environment.Production:
                    baseUri = new Uri("https://ident.familysearch.org/cis-web/oauth2/v3/authorization");
                    break;
                case Environment.Beta:
                    baseUri = new Uri("https://identbeta.familysearch.org/cis-web/oauth2/v3/authorization");
                    break;
                case Environment.Integration:
                    baseUri = new Uri("https://identint.familysearch.org/cis-web/oauth2/v3/authorization");
                    break;
            }
        }
        else if (setType == "Token")
        {
            switch (devEnvironment)
            {
                case Environment.Production:
                    baseUri = new Uri("https://ident.familysearch.org/cis-web/oauth2/v3/token");
                    break;
                case Environment.Beta:
                    baseUri = new Uri("https://identbeta.familysearch.org/cis-web/oauth2/v3/token");
                    break;
                case Environment.Integration:
                    baseUri = new Uri("https://identint.familysearch.org/cis-web/oauth2/v3/token");
                    break;
            }
        }
        else if (setType == "Regular")
        {
            switch (devEnvironment)
            {
                case Environment.Production:
                    baseUri = new Uri("https://api.familysearch.org/");
                    break;
                case Environment.Beta:
                    baseUri = new Uri("https://apibeta.familysearch.org/");
                    break;
                case Environment.Integration:
                    baseUri = new Uri("https://api-integ.familysearch.org/");
                    break;
            }
        }
    }

    private static string GenerateRandom(uint length)
    {
        byte[] bytes = new byte[length];
        RandomNumberGenerator.Create().GetBytes(bytes);
        return EncodeNoPadding(bytes);
    }

    private static string EncodeNoPadding(byte[] buffer)
    {
        string toEncode = Convert.ToBase64String(buffer);

        toEncode = toEncode.Replace("+", "-");
        toEncode = toEncode.Replace("/", "_");

        toEncode = toEncode.Replace("=", "");

        return toEncode;
    }

    private static byte[] GenerateSha256(string inputString)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(inputString);
        SHA256 sha256 = SHA256.Create();
        return sha256.ComputeHash(bytes);
    }

    public void InitAuth()
    {
        switch (isFirstLoad)
        {
            case true:
                {
                    isFirstLoad = false;
                    SetBaseURL("Auth");

                    code_verifier = GenerateRandom(32);
                    code_challenge = EncodeNoPadding(GenerateSha256(code_verifier));
                    userID = null;

                    StartOAuth();
                    break;
                }
            case false:
                {
                    break;
                }
        }
    }

    private void StartOAuth()
    {
#if UNITY_WEBGL
        string redirectUri = "";

        string authRequest = string.Format("{0}?client_id={1}&redirect_uri={2}&response_type=code&state={3}&code_challenge={4}&code_challenge_method=S256&scope=openid",
        baseUri,
        client_id,
        redirectUri,
        outState,
        code_challenge);
        Debug.Log(authRequest);
        StartAuthentication(authRequest);

#elif UNITY_EDITOR || UNITY_STANDALONE_WIN
        string redirectUri = "http://127.0.0.1:5000";
        string redirectUriListener = "http://127.0.0.1:5000/";

        httpListener = new HttpListener();
        httpListener.Prefixes.Add(redirectUriListener);

        string authRequest = string.Format("{0}?client_id={1}&redirect_uri={2}&response_type=code&state={3}&code_challenge={4}&code_challenge_method=S256&scope=openid",
         baseUri,
         client_id,
         redirectUri,
         outState,
         code_challenge);

        httpListener.Start();

        Application.OpenURL(authRequest);

        HttpListenerContext context = httpListener.GetContext();
        HttpListenerResponse response = context.Response;

        string responseString = "<HTML><HEAD><SCRIPT>window.close();</SCRIPT></HEAD><BODY></BODY></HTML>";
        byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
        response.ContentLength64 = buffer.Length;
        System.IO.Stream output = response.OutputStream;
        output.Write(buffer, 0, buffer.Length);
        output.Close();

        httpListener.Stop();

        authorizationCode = context.Request.QueryString.Get("code");
        string inState = context.Request.QueryString.Get("state");

        if (inState == outState)
        {
            StartCoroutine(ExchangeCodeForToken());
            StartCoroutine(GetCurrentUser());
            StartCoroutine(SignInWithOpenId());
        }
#endif
    }

    public void GetAuthResultsWebGL(string result)
    {
        string[] response = result.Split('?');

        response = response[1].Split("&");

        string[] authResponse = response[0].Split("=");
        string[] stateResponse = response[1].Split("=");

        if (stateResponse[1] == outState)
        {
            authorizationCode = authResponse[1];
            StartCoroutine(ExchangeCodeForToken());
            StartCoroutine(GetCurrentUser());
            StartCoroutine(SignInWithOpenId());
        }
    }

    private IEnumerator ExchangeCodeForToken()
    {
        do
        {
            if (string.IsNullOrEmpty(authorizationCode))
            {
                yield return new WaitForSeconds(0.001f);
            }
        }
        while (string.IsNullOrEmpty(authorizationCode));

        SetBaseURL("Token");

        exchangeFinished = false;

        Dictionary<string, string> formData = new Dictionary<string, string>();
        formData.Add("code", authorizationCode);
        formData.Add("grant_type", "authorization_code");
        formData.Add("client_id", client_id);
        formData.Add("code_verifier", code_verifier);

        authorizationCode = null;

        webRequest = UnityWebRequest.Post(baseUri, formData);
        webRequest.SetRequestHeader("Accept", "application/json");
        webRequest.SetRequestHeader("Content-Type", "application/x-www-form-urlencoded");

        webRequest.downloadHandler = new DownloadHandlerBuffer();

        asyncOperation = webRequest.SendWebRequest();
        asyncOperation.completed += (AsyncOperation op) => { ExchangeResponse(asyncOperation); };
    }

    private void ExchangeResponse(UnityWebRequestAsyncOperation op)
    {
        accessToken = JsonConvert.DeserializeObject<AccessToken>(op.webRequest.downloadHandler.text);
        exchangeFinished = true;
    }

    public void SetPid(string pID)
    {
        pidToLoad = pID;
    }

    private IEnumerator SignInWithOpenId()
    {
        do
        {
            yield return new WaitForSeconds(0.01f);
        }
        while (!exchangeFinished);

        var task = UnityServicesHelper.SignInWithOpenIdAsync(accessToken.id_token);
        yield return new WaitUntil(() => task.IsCompleted);
    }

    private IEnumerator GetCurrentUser()
    {
        do
        {
            yield return new WaitForSeconds(0.001f);
        }
        while (!exchangeFinished);

        SetBaseURL("Regular");
        string apiRoute = "platform/users/current";
        string request = string.Format("{0}{1}", baseUri, apiRoute);
        
        webRequest = UnityWebRequest.Get(request);
        webRequest.SetRequestHeader("Accept", "application/json");
        webRequest.SetRequestHeader("Authorization", "Bearer " + accessToken.access_token);

        webRequest.downloadHandler = new DownloadHandlerBuffer();

        asyncOperation = webRequest.SendWebRequest();
        asyncOperation.completed += (AsyncOperation op) => { CurrentUserResponse(asyncOperation); };
    }

    private void CurrentUserResponse(UnityWebRequestAsyncOperation op)
    {
        CurrentUserRoot currentUserRoot = JsonConvert.DeserializeObject<CurrentUserRoot>(op.webRequest.downloadHandler.text);
        userID = currentUserRoot.users[0].personId;
    }

    public string GetUserID()
    {
        return userID;
    }

    public void GetMemories()
    {
        SetBaseURL("Regular");

        string apiRoute = "platform/tree/persons/";
        string memoryCount = "/memories?start=";
        string countString = MemoryManager.Instance.GetMemoryCount();

        string request = string.Format("{0}{1}{2}{3}{4}",
            baseUri,
            apiRoute,
            pidToLoad,
            memoryCount,
            countString);

        webRequest = UnityWebRequest.Get(request);
        webRequest.SetRequestHeader("Accept", "application/json");
        webRequest.SetRequestHeader("Authorization", "Bearer " + accessToken.access_token);

        webRequest.downloadHandler = new DownloadHandlerBuffer();

        asyncOperation = webRequest.SendWebRequest();
        asyncOperation.completed += (AsyncOperation op) => { MemoriesResponse(asyncOperation); };
    }

    private void MemoriesResponse(UnityWebRequestAsyncOperation op)
    {
        if (op.webRequest.responseCode == 200)
        {
            MemoryManager.Instance.SetMemorySet(op.webRequest.downloadHandler.text);
            GetMemories();
        }
        else if (op.webRequest.responseCode == 204)
        {
            GameManager.Instance.ResponseReceived();
        }
    }

    public void GetImage(string location)
    {
        webRequest = UnityWebRequest.Get(location);

        webRequest.downloadHandler = new DownloadHandlerBuffer();
        asyncOperation = webRequest.SendWebRequest();
        asyncOperation.completed += (AsyncOperation op) => { GetImageResponse(asyncOperation); };
    }

    private void GetImageResponse(UnityWebRequestAsyncOperation op)
    {
        ImageManager.Instance.ImageReceived(op.webRequest.downloadHandler.data);
    }

    public IEnumerator GetAudio(string location)
    {
        webRequest = UnityWebRequestMultimedia.GetAudioClip(location, AudioType.MPEG);
        yield return webRequest.SendWebRequest();
        AudioManager.Instance.AudioReceived(DownloadHandlerAudioClip.GetContent(webRequest));
    }

    public void CheckAncestorDeceased()
    {
        string apiRoute = "platform/tree/persons/";
        string request = string.Format("{0}{1}{2}",
            baseUri,
            apiRoute,
            pidToLoad);

        webRequest = UnityWebRequest.Get(request);
        webRequest.SetRequestHeader("Accept", "application/x-gedcomx-v1+json");
        webRequest.SetRequestHeader("Authorization", "Bearer " + accessToken.access_token);

        webRequest.downloadHandler = new DownloadHandlerBuffer();

        asyncOperation = webRequest.SendWebRequest();
        asyncOperation.completed += (AsyncOperation op) => { AncestorDeceasedResponse(asyncOperation); };
    }

    private void AncestorDeceasedResponse(UnityWebRequestAsyncOperation op)
    {
        if (op.webRequest.responseCode == 200)
        {
            CheckPersonResource.CheckPersonJson checkPersonJson = JsonConvert.DeserializeObject<CheckPersonResource.CheckPersonJson>(op.webRequest.downloadHandler.text);

            if (checkPersonJson.persons[0].living == false)
            {
                TextMemoryManager.Instance.AncestorDeceased(checkPersonJson.persons[0].display.gender);
            }
        }
    }

    public void GetTextMemory(string memoryLocation)
    {
        webRequest = UnityWebRequest.Get(memoryLocation);

        webRequest.downloadHandler = new DownloadHandlerBuffer();
        asyncOperation = webRequest.SendWebRequest();
        asyncOperation.completed += (AsyncOperation op) => { TextResponse(asyncOperation); };
    }

    private void TextResponse(UnityWebRequestAsyncOperation op)
    {
        if (op.webRequest.responseCode == 200)
        {
            TextMemoryManager.Instance.TextReceived(op.webRequest.downloadHandler.text);
        }
        else
        {
            TextMemoryManager.Instance.TextNotReceived();
        }
    }

}

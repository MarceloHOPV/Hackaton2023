const { match } = require('assert');
const { app, BrowserWindow } = require('electron');
const net = require('net');

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      nodeIntegrationInWorker: true,
      contextIsolation: false,
    },
  });

  const client = net.connect(50000, '127.0.0.1', () => {
    console.log('Connected to server');
  });
  const valores = {};
  var str;//nossa string
  var upload = [];
  var size;
  var contn = 0;

  function adicionarValor(chave, valor) {
    if (valores[chave] === undefined) {
      valores[chave] = valor;
    } else {
      valores[chave] += valor;
    }
  }
  
  function obterValor(chave) {
    return valores[chave] || 0;
  }

  client.on('data', (data) => {
    //mainWindow.webContents.send('message', data.toString());
    //str = data.toString().slice(0,192);//cortando a parte que não queremos
    //size = str.length;//pegando o tamanho da string
    //str = str.toString().split("} ] }");
    str = data.toString();//declarando a strig
    //código para cortar a parte que não utilizaremos da string
    //str = "ola } ] }  \"name\": \"opera.exe\", dasd  asdasd \"name\": \"opera.exe\", } ] } café\"name\": \"altium.exe\"," // string teste
    //str = str.split("} ] }") // separando os programas
    //console.log(str[1]);//printa no console a parte que quermos

var regexm = /"name": "(.*?).exe",/g;//regex para achar o nome
var matches = str.match(regexm);//declarando matches
var regexd = /"download": "(.*?)KB",/g;//regex que reconhecera a sequecia nome..download: "num" kb
//vetor que armazena os valores inteiro do download
var matchesD = str.match(regexd);
var Nomes = [];//declarando a variavel que vai pegar os nomes individualmente
//se deu match:
if (matches) {
  //separando os mashs e dando push para um vetore Nomes
  for (let i = 0; i < matches.length; i++) {
    var match = matches[i];
    var valor = match.split(':')[1].trim();
    adicionarValor(valor,contn);
    Nomes.push(valor);
    contn = contn+1;
  }
}var NomesSemRepeticao = [...new Set(Nomes)];
  
const downloads = NomesSemRepeticao.map((nome) => {
  regexd.lastIndex = 0; // redefinir o índice do regex para a busca correta
  let matchD;

  while ((matchD = regexd.exec(str)) !== null) {
    const valorD = matchD[1].trim();
    const valorCortado = parseInt(valorD.split("KB")[0]);
    if (obterValor(nome) !== 0) {
      adicionarValor(nome, valorCortado);
    }
  }

  return obterValor(nome);
});

    
  
  

//setando nomes para que não tenha repetições

//printando os nomes no console
console.log(NomesSemRepeticao);
console.log(downloads);
mainWindow.webContents.send('message', `${NomesSemRepeticao} ----- > ${downloads}`);
//-------------------------------------------------------


  


});

  mainWindow.loadFile('index.html');

  mainWindow.webContents.openDevTools();
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
